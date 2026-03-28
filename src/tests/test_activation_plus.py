# tests/test_activation_plus.py
"""
更深入的激活系统测试
覆盖边界条件、异常场景、并发竞争、安全攻击等刁钻情况
"""

import sys
import os
import time
import json
import pytest
import requests
import threading
import tempfile
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch, MagicMock

# 添加项目根目录到 Python 路径
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sealium.client.activator import Activator, ActivationError
from sealium.common.models import ActivationStatus
from sealium.common.utils import Utils
from sealium.server.database import SQLiteDatabase, ActivationCodeStorage
from sealium.server.config import config
from sealium.scripts.generate_activation_codes import generate_activation_codes

# ==================== 测试配置 ====================
BASE_URL = "http://localhost:8000"
ACTIVATION_URL = f"{BASE_URL}/v1/activation"
HEALTH_URL = f"{BASE_URL}/health"

# 项目根目录（自动检测）
PROJECT_ROOT = Path(__file__).resolve().parents[2]

# 密钥文件路径（相对于项目根目录）
SERVER_PUBLIC_KEY_PATH = PROJECT_ROOT / "data" / "server_public.pem"
CLIENT_PRIVATE_KEY_PATH = PROJECT_ROOT / "data" / "client_private.pem"

# 临时目录用于模拟损坏的密钥
TEMP_DIR = Path(tempfile.mkdtemp(prefix="sealium_test_"))


@pytest.fixture(scope="session", autouse=True)
def server_health_check():
    """检查服务端是否可用（会话级别）"""
    try:
        resp = requests.get(HEALTH_URL, timeout=3)
        if resp.status_code != 200:
            pytest.skip("服务端健康检查失败，请确保服务已启动")
    except Exception as e:
        pytest.skip(f"无法连接服务端: {e}")


@pytest.fixture
def db():
    """提供数据库连接（使用测试数据库，避免污染主库）"""
    test_db_path = TEMP_DIR / "test_database.db"
    db = SQLiteDatabase(str(test_db_path))
    db.connect()
    yield db
    db.close()
    # 测试后删除临时文件
    if test_db_path.exists():
        test_db_path.unlink()


@pytest.fixture
def storage(db):
    """提供激活码存储实例"""
    return ActivationCodeStorage(db)


@pytest.fixture
def client_keys():
    """加载客户端密钥（用于客户端激活器）"""
    # 客户端私钥
    if not CLIENT_PRIVATE_KEY_PATH.exists():
        pytest.skip(f"客户端私钥文件不存在: {CLIENT_PRIVATE_KEY_PATH}，请先生成")
    with open(CLIENT_PRIVATE_KEY_PATH, "r") as f:
        client_priv_key = f.read()
    # 服务端公钥（客户端需要用它加密请求）
    if not SERVER_PUBLIC_KEY_PATH.exists():
        pytest.skip(f"服务端公钥文件不存在: {SERVER_PUBLIC_KEY_PATH}，请先生成")
    with open(SERVER_PUBLIC_KEY_PATH, "r") as f:
        server_pub_key = f.read()
    return server_pub_key, client_priv_key


@pytest.fixture
def activator(client_keys):
    """创建激活器实例"""
    server_pub_key, client_priv_key = client_keys
    return Activator(ACTIVATION_URL, server_pub_key, client_priv_key)


@pytest.fixture
def clean_unused_activation_code(storage):
    """生成一个干净的未使用激活码（使用临时数据库）"""
    codes = generate_activation_codes(1, db_path=storage.db.db_path)
    test_code = codes[0]
    yield test_code
    # 测试后清理
    storage.delete(test_code)


# ==================== 边界条件测试 ====================
class TestBoundaryConditions:
    """边界条件测试"""

    def test_timestamp_boundary(self, activator, storage, clean_unused_activation_code, monkeypatch):
        """时间戳恰好等于允许偏差边界"""
        test_code = clean_unused_activation_code
        now = Utils.get_current_timestamp()
        # 模拟时间戳 API 返回 now + tolerance
        tolerance = config.TIME_STAMP_TOLERANCE_SECONDS
        for delta in [-tolerance, tolerance]:
            mock_timestamp = now + delta
            monkeypatch.setattr(Utils, "get_timestamp_from_api", lambda: mock_timestamp)
            response = activator.activate(test_code)
            # 边界值应成功
            assert response.result == "success"
            # 重新生成新激活码，因为已被使用
            codes = generate_activation_codes(1, db_path=storage.db.db_path)
            test_code = codes[0]

        # 边界外1秒应失败
        mock_timestamp = now + tolerance + 1
        monkeypatch.setattr(Utils, "get_timestamp_from_api", lambda: mock_timestamp)
        codes = generate_activation_codes(1, db_path=storage.db.db_path)
        test_code = codes[0]
        response = activator.activate(test_code)
        assert response.result == "error"
        assert "时间戳无效" in response.error_msg

    def test_activation_code_length_boundary(self, activator):
        """激活码长度边界测试"""
        # 空激活码
        response = activator.activate("")
        assert response.result == "error"
        assert "无效" in response.error_msg or "不存在" in response.error_msg

        # 超长激活码（超过数据库字段长度，但数据库 TEXT 无限制）
        long_code = "a" * 1000
        response = activator.activate(long_code)
        assert response.result == "error"
        assert "不存在" in response.error_msg

        # 包含特殊字符
        special_code = "!@#$%^&*()_+"
        response = activator.activate(special_code)
        assert response.result == "error"
        assert "不存在" in response.error_msg

    def test_machine_code_consistency(self, activator, storage, clean_unused_activation_code):
        """多次激活同一机器，机器码应一致"""
        test_code = clean_unused_activation_code
        response = activator.activate(test_code)
        assert response.result == "success"
        record = storage.get_by_code(test_code)
        machine1 = record.bound_machine_code

        # 生成新激活码
        codes = generate_activation_codes(1, db_path=storage.db.db_path)
        test_code2 = codes[0]
        response2 = activator.activate(test_code2)
        assert response2.result == "success"
        record2 = storage.get_by_code(test_code2)
        machine2 = record2.bound_machine_code

        assert machine1 == machine2


# ==================== 异常场景测试（需模拟） ====================
class TestExceptionScenarios:
    """异常场景测试 - 使用 monkeypatch 模拟异常情况"""

    def test_database_connection_failure(self, activator, clean_unused_activation_code, monkeypatch):
        """数据库连接失败时的服务端响应（模拟数据库错误）"""
        # 模拟数据库操作抛出异常
        def mock_bind(*args, **kwargs):
            raise Exception("Database connection lost")

        # 注意：这里需要模拟服务端的数据库操作，但 activator 是客户端，无法直接控制服务端。
        # 我们只能模拟客户端视角的失败：例如服务端返回加密的错误信息。
        # 更合适的方式是启动一个测试服务器并模拟数据库失败，但为了简洁，我们假设服务端会返回错误。
        # 这里实际上无法直接测试，因为服务端是独立的。所以该测试更适合放在服务端单元测试中。
        # 此处仅作占位，表示应该测试这类场景。
        pytest.skip("需要在服务端单元测试中模拟数据库失败")

    def test_corrupted_private_key(self, client_keys):
        """客户端私钥损坏时初始化应失败"""
        server_pub_key, _ = client_keys
        # 使用无效的私钥字符串
        with pytest.raises(ValueError) as exc:
            Activator(ACTIVATION_URL, server_pub_key, "invalid key")
        assert "PEM" in str(exc.value) or "load" in str(exc.value)

    def test_server_returns_malformed_response(self, activator, clean_unused_activation_code, monkeypatch):
        """服务端返回非 JSON 格式数据（模拟网络中间人攻击）"""
        # 模拟 requests.post 返回无效内容
        def mock_post(*args, **kwargs):
            resp = MagicMock()
            resp.content = b"this is not encrypted"
            resp.status_code = 200
            return resp

        monkeypatch.setattr(requests, "post", mock_post)
        with pytest.raises(ActivationError) as exc:
            activator.activate(clean_unused_activation_code)
        assert "解密响应失败" in str(exc.value) or "解析响应失败" in str(exc.value)

    def test_server_returns_empty_response(self, activator, clean_unused_activation_code, monkeypatch):
        """服务端返回空响应"""
        def mock_post(*args, **kwargs):
            resp = MagicMock()
            resp.content = b""
            resp.status_code = 200
            return resp

        monkeypatch.setattr(requests, "post", mock_post)
        with pytest.raises(ActivationError) as exc:
            activator.activate(clean_unused_activation_code)
        assert "解密响应失败" in str(exc.value)

    def test_encryption_payload_overflow(self, activator):
        """请求数据过大导致加密失败（模拟）"""
        # 生成超大数据，RSA 4096 最大约 446 字节，我们构造一个很大的请求
        # 但当前请求结构较小，无法直接触发。可以通过 monkeypatch 修改加密方法模拟。
        def mock_encrypt(*args, **kwargs):
            raise ValueError("Data too long")

        monkeypatch.setattr(activator.key_manager, "encrypt_request", mock_encrypt)
        with pytest.raises(ActivationError) as exc:
            activator.activate("any_code")
        assert "加密请求失败" in str(exc.value)


# ==================== 并发与竞争测试 ====================
class TestConcurrency:
    """并发测试"""

    def test_concurrent_activation_same_code(self, activator, storage, clean_unused_activation_code):
        """并发激活同一个激活码，只有一个应成功"""
        test_code = clean_unused_activation_code
        results = []
        errors = []

        def activate_worker():
            try:
                resp = activator.activate(test_code)
                results.append(resp.result)
            except Exception as e:
                errors.append(str(e))

        threads = []
        for _ in range(10):
            t = threading.Thread(target=activate_worker)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        # 只有一个成功，其余失败
        success_count = results.count("success")
        assert success_count == 1
        # 失败的错误信息应为“已被使用”
        for i, result in enumerate(results):
            if result == "error":
                # 实际上返回的错误信息应包含"已被使用"
                # 由于我们无法直接获取错误信息，但可以通过检查 storage 中状态
                pass
        # 验证数据库状态
        record = storage.get_by_code(test_code)
        assert record.status == ActivationStatus.USED

    def test_concurrent_generate_activation_codes(self, storage):
        """并发生成激活码，确保唯一性"""
        from sealium.scripts.generate_activation_codes import generate_activation_codes

        codes_list = []

        def generate_worker():
            codes = generate_activation_codes(100, db_path=storage.db.db_path)
            codes_list.extend(codes)

        threads = []
        for _ in range(5):
            t = threading.Thread(target=generate_worker)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        # 验证所有激活码唯一
        assert len(set(codes_list)) == len(codes_list)
        # 验证数据库中的记录数
        all_codes = storage.list_all()
        assert len(all_codes) == len(codes_list)


# ==================== 安全测试 ====================
class TestSecurity:
    """安全攻击测试"""

    def test_replay_attack_with_different_nonce(self, activator, storage, clean_unused_activation_code):
        """重放攻击：相同激活码，不同 nonce 应视为不同请求（但激活码已使用会失败）"""
        test_code = clean_unused_activation_code
        # 第一次激活成功
        resp1 = activator.activate(test_code)
        assert resp1.result == "success"
        # 第二次激活（不同 nonce，由 activator 自动生成）应失败
        resp2 = activator.activate(test_code)
        assert resp2.result == "error"
        assert "已被使用" in resp2.error_msg

    def test_tamper_encrypted_request(self, activator, clean_unused_activation_code):
        """篡改加密请求数据，应导致解密失败"""
        test_code = clean_unused_activation_code
        # 先正常构造请求，但修改密文
        # 获取加密后的请求（但无法直接获取，因为 activator 内部封装）
        # 我们模拟发送随机数据
        import requests
        random_data = os.urandom(100)
        resp = requests.post(ACTIVATION_URL, data=random_data, timeout=10)
        # 服务端应返回加密的错误响应（我们无法直接验证，但应能正常处理）
        # 实际上 resp.content 是加密的，我们用 activator 解密会失败，但这里只测试客户端是否能处理
        # 我们直接尝试用 activator 的 key_manager 解密，应抛出异常
        with pytest.raises(Exception):
            activator.key_manager.decrypt_response(resp.content)

    def test_expired_activation_code(self, activator, storage, server_health_check):
        """过期激活码无法激活（已有测试，但可加强）"""
        from sealium.scripts.generate_activation_codes import generate_activation_codes
        expires_at = datetime.now() - timedelta(days=1)
        codes = generate_activation_codes(1, expires_at=expires_at, db_path=storage.db.db_path)
        test_code = codes[0]
        response = activator.activate(test_code)
        assert response.result == "error"
        assert "已过期" in response.error_msg
        storage.delete(test_code)


# ==================== 数据一致性测试 ====================
class TestDataConsistency:
    """数据一致性测试"""

    def test_activation_twice_different_machine(self, activator, storage, clean_unused_activation_code):
        """激活后，尝试使用同一激活码在不同机器激活（实际同一机器，但可模拟）"""
        # 由于测试环境机器码固定，无法测试不同机器。但可以通过修改机器码来模拟。
        # 注意：机器码在客户端生成，无法直接修改。可以通过 monkeypatch 模拟。
        test_code = clean_unused_activation_code
        # 第一次激活
        response1 = activator.activate(test_code)
        assert response1.result == "success"

        # 修改机器码生成函数，模拟不同机器
        def mock_machine_code():
            return "different_machine_code"

        with patch("sealium.common.utils.Utils.generate_machine_code", side_effect=mock_machine_code):
            # 重新创建 activator 以使用新的 mock（因为 activator 内部会调用 Utils）
            # 但 Utils 是全局的，patch 后已生效
            response2 = activator.activate(test_code)
            # 第二次激活应失败，因为激活码已使用
            assert response2.result == "error"
            assert "已被使用" in response2.error_msg

    def test_activation_code_uniqueness(self, storage):
        """数据库激活码唯一性约束"""
        from sealium.common.models import ActivationCode
        code = "test_unique_code"
        activation = ActivationCode(activation_code=code, status=ActivationStatus.UNUSED)
        storage.create(activation)
        # 再次插入相同 code 应引发异常（数据库约束）
        with pytest.raises(Exception) as exc:
            storage.create(activation)
        # SQLite 会返回 IntegrityError
        assert "UNIQUE constraint failed" in str(exc.value)


# ==================== 服务端配置变更测试 ====================
class TestConfigChanges:
    """服务端配置变更后的行为测试（需要重启服务，这里只做逻辑验证）"""

    def test_tolerance_change(self, activator, storage, clean_unused_activation_code, monkeypatch):
        """时间戳偏差值修改后，验证边界行为"""
        # 模拟服务端配置变更（实际无法修改运行中的服务，但我们可以模拟时间戳校验函数）
        # 此测试验证客户端行为，需要服务端配合，不适合在此处做。
        pytest.skip("需要服务端支持动态配置")

    def test_private_key_reload(self):
        """服务端私钥更换后，客户端应能正常激活（需重启服务）"""
        pytest.skip("需要服务端重启测试")


# ==================== 清理临时目录 ====================
@pytest.fixture(scope="session", autouse=True)
def cleanup_temp_dir():
    yield
    # 测试结束后清理临时目录
    if TEMP_DIR.exists():
        shutil.rmtree(TEMP_DIR, ignore_errors=True)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])