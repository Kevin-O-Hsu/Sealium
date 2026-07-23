# tests/conftest.py
"""
共享 pytest fixtures。

设计目标：测试套件**完全离线运行**——
* RSA 密钥对在 session 级生成一次（4096 位，匹配协议默认）；
* 数据库是每个测试独立的临时 SQLite 文件；
* 服务端用 FastAPI ``TestClient`` 进程内驱动，无需启动真实 uvicorn；
* 时间源、机器码均可注入，避免依赖网络/硬件。
"""

from __future__ import annotations

from datetime import datetime
import os
from pathlib import Path
from urllib.parse import urlparse

import pytest
from fastapi.testclient import TestClient

# LOW-003：硬件指纹 pepper 现为强制运行时配置（未设 MACHINE_ID_PEPPER 时生成
# 指纹抛错）。测试套件需固定 pepper，且必须在首次 import sealium 之前设置
#（import 之后设置无效，见 client-guide §9）。setdefault 不覆盖生产环境已设值。
os.environ.setdefault("MACHINE_ID_PEPPER", "sealium-test-fingerprint-pepper")

from sealium.client.activator import Activator
from sealium.common.crypto import RSAEncryptor
from sealium.common.fingerprint import Component, MachineFingerprint
from sealium.server.app import create_app
from sealium.server.config import (
    ServerConfig,
    ServerModel,
    PathsModel,
    SecurityModel,
    RateLimitModel,
    LoggingModel,
    CorsModel,
)
from sealium.server.database import ActivationCodeStorage, SQLiteDatabase

# 固定的“当前时间”，便于时间戳/过期断言
FIXED_DT = datetime(2026, 1, 1, 12, 0, 0)
FIXED_TS = int(FIXED_DT.timestamp())


# ==================== 时间 ====================
@pytest.fixture
def fixed_now() -> datetime:
    return FIXED_DT


@pytest.fixture
def fixed_timestamp() -> int:
    return FIXED_TS


# ==================== 密钥 ====================
@pytest.fixture(scope="session")
def server_keypair() -> RSAEncryptor:
    """4096 位 RSA 密钥对（session 级，整个测试套件只生成一次）。"""
    return RSAEncryptor.generate()  # 默认 4096


@pytest.fixture(scope="session")
def server_private_pem(server_keypair: RSAEncryptor) -> bytes:
    return server_keypair.export_private_key()


@pytest.fixture(scope="session")
def server_public_pem(server_keypair: RSAEncryptor) -> str:
    return server_keypair.export_public_key().decode()


@pytest.fixture
def server_private_key_file(tmp_path: Path, server_private_pem: bytes) -> Path:
    """私钥写入临时文件（用于测试 config.validate / 真实加载路径）。"""
    path = tmp_path / "server_private.pem"
    path.write_bytes(server_private_pem)
    return path


# ==================== 数据库 ====================
@pytest.fixture
def db(tmp_path: Path) -> SQLiteDatabase:
    """临时 SQLite 数据库（function 级隔离，测试互不干扰）。"""
    database = SQLiteDatabase(tmp_path / "test.db")
    database.connect()
    database.init_tables()
    yield database
    database.close()


@pytest.fixture
def storage(db: SQLiteDatabase) -> ActivationCodeStorage:
    return ActivationCodeStorage(db)


# ==================== 服务端应用 / TestClient ====================
def isolated_config(base_dir: Path) -> ServerConfig:
    """构造一个不触碰真实文件的隔离配置（指向临时目录，bypass 文件加载）。"""
    return ServerConfig(
        server=ServerModel(
            host="127.0.0.1",
            port=8000,
            debug=False,
            api_prefix="/v1",
            activation_path="/activation",
        ),
        paths=PathsModel(
            database=base_dir / "test.db",
            private_key=base_dir / "server_private.pem",
            public_key=None,
        ),
        security=SecurityModel(),
        rate_limit=RateLimitModel(enabled=False),  # 测试默认关闭限流，保证确定性
        logging=LoggingModel(level="WARNING", format="%(message)s"),
        cors=CorsModel(),
    )


@pytest.fixture
def make_app(server_keypair: RSAEncryptor):
    """
    返回一个应用工厂：可自定义 storage / replay_guard / now_provider / config。
    默认注入固定时间，便于时间戳断言。
    """

    def _make(
        storage: ActivationCodeStorage,
        *,
        replay_guard=None,
        now_provider=None,
        config: ServerConfig | None = None,
    ):
        cfg = config or isolated_config(Path(storage.db.db_path).parent)
        return create_app(
            config=cfg,
            encryptor=server_keypair,
            storage=storage,
            replay_guard=replay_guard,
            now_provider=now_provider or (lambda: FIXED_DT),
        )

    return _make


@pytest.fixture
def client(make_app, storage: ActivationCodeStorage):
    """进程内 TestClient（注入密钥 / DB / 固定时间），无需真实服务端。"""
    app = make_app(storage)
    with TestClient(app) as test_client:
        yield test_client


# ==================== 客户端 ====================
@pytest.fixture
def make_fingerprint():
    """
    返回测试指纹构造器：相同 ``seed`` → 相同核心分量；``drift=True`` → 外围分量与基准
    不同（用于同机漂移场景）；``spoof`` 设 spoof_score。分量 value 用可读字符串
    （非哈希），因测试只关心匹配逻辑（值相等即匹配）。
    """

    def _make_fp(seed: str = "m", *, spoof: float = 0.0, drift: bool = False) -> MachineFingerprint:
        core_val = f"core-{seed}"
        periph_val = f"periph-drift-{seed}" if drift else f"periph-{seed}"
        return MachineFingerprint(
            components=(
                Component("cpu", core_val, True),
                Component("board", core_val, True),
                Component("bios", core_val, True),
                Component("system_uuid", core_val, True),
                Component("disk", periph_val, False),
                Component("mac", periph_val, False),
            ),
            spoof_score=spoof,
        )

    return _make_fp


@pytest.fixture
def make_activator(server_public_pem: str, make_fingerprint):
    """
    返回一个 Activator 工厂：HTTP 通过桥接打到 TestClient，时间/机器码可注入。
    """

    def _make(test_client: TestClient, *, timestamp: int = FIXED_TS, machine_code: MachineFingerprint | None = None) -> Activator:
        fp = machine_code if machine_code is not None else make_fingerprint()

        def poster(url, data, headers, timeout):
            return test_client.post(urlparse(url).path, content=data, headers=headers)

        return Activator(
            "http://localhost/v1/activation",
            server_public_pem,
            timestamp_provider=lambda: timestamp,
            machine_code_provider=lambda: fp,
            http_poster=poster,
        )

    return _make


@pytest.fixture
def unused_code(storage: ActivationCodeStorage) -> str:
    """在临时库中创建一个未使用的激活码，返回码字符串。"""
    from sealium.common.models import ActivationCode, ActivationStatus

    code = "a" * 32
    storage.create(
        ActivationCode(
            activation_code=code,
            status=ActivationStatus.UNUSED,
            features=["pro"],
            expires_at=datetime(2026, 12, 31),
        )
    )
    return code
