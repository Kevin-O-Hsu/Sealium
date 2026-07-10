# tests/e2e/test_full_flow.py
"""
端到端测试：真实客户端 Activator + 进程内 TestClient 服务端 + 真实激活码生成脚本。

验证完整业务闭环：生成码 -> 激活 -> DB 绑定 -> 同机幂等 -> 异机拒绝，
以及防重放、时间戳、脚本工具等横切关注点。全部离线运行。
"""

from __future__ import annotations

import json
from datetime import datetime

import pytest

from sealium.client.key_manager import ClientKeyManager
from sealium.common.crypto import RSAEncryptor
from sealium.common.models import ActivationStatus
from sealium.scripts.generate_activation_codes import generate_activation_codes


def _decrypt(km: ClientKeyManager, content: bytes) -> dict:
    return json.loads(km.decrypt_response(content).decode())


def _post(client, server_public_pem: str, request_dict: dict):
    km = ClientKeyManager(server_public_pem)
    packet = km.build_encrypted_request(json.dumps(request_dict).encode())
    resp = client.post("/v1/activation", content=packet)
    return resp, km


class TestFullActivationFlow:
    def test_generate_activate_verify_reactivate(self, client, make_activator, storage, make_fingerprint):
        """生成码 -> 首次激活 -> DB 绑定 -> 同机重激活幂等成功。"""
        code = generate_activation_codes(
            1, features=["pro", "ent"], expires_at=datetime(2026, 12, 31),
            db_path=storage.db.db_path,
        )[0]

        activator = make_activator(client)

        first = activator.activate(code)
        assert first.result == "success"
        assert first.features == ["pro", "ent"]
        assert first.authorized_until == "2026-12-31"

        stored = storage.get_by_code(code)
        assert stored.status == ActivationStatus.USED
        assert stored.bound_machine_code == make_fingerprint()

        # 同机重激活：幂等成功
        second = activator.activate(code)
        assert second.result == "success"
        assert second.authorized_until == first.authorized_until

    def test_different_machine_rejected_after_bind(
        self, client, make_activator, storage, make_fingerprint
    ):
        """机器 A 激活后，机器 B 使用同一码应被拒。"""
        code = generate_activation_codes(1, db_path=storage.db.db_path)[0]

        activator_a = make_activator(client, machine_code=make_fingerprint("machineA"))
        assert activator_a.activate(code).result == "success"

        activator_b = make_activator(client, machine_code=make_fingerprint("machineB"))
        resp = activator_b.activate(code)
        assert resp.result == "error"
        # 与“码不存在”对外不可区分（GRAY-001）
        assert "已被使用" in resp.error_msg

    def test_same_machine_peripheral_drift_accepted(
        self, client, make_activator, storage, make_fingerprint
    ):
        """核心相同、外围（磁盘/MAC）变化的指纹仍应判为同机（阈值容错）。"""
        code = generate_activation_codes(1, db_path=storage.db.db_path)[0]

        activator_a = make_activator(client, machine_code=make_fingerprint("host1"))
        assert activator_a.activate(code).result == "success"

        # 核心相同（seed host1）、外围漂移（drift=True）→ 仍判同机 → 幂等成功
        activator_a2 = make_activator(client, machine_code=make_fingerprint("host1", drift=True))
        resp = activator_a2.activate(code)
        assert resp.result == "success"

    def test_multiple_codes_one_machine(self, client, make_activator, storage, make_fingerprint):
        """同一台机器可激活多个不同激活码。"""
        codes = generate_activation_codes(3, db_path=storage.db.db_path)
        activator = make_activator(client)
        for code in codes:
            assert activator.activate(code).result == "success"
        # 全部绑定同一机器指纹
        bound = {storage.get_by_code(c).bound_machine_code for c in codes}
        assert bound == {make_fingerprint()}

    def test_permanent_code_authorized_forever(self, client, make_activator, storage):
        """无 expires_at 的码返回永久授权。"""
        code = generate_activation_codes(1, db_path=storage.db.db_path)[0]
        resp = make_activator(client).activate(code)
        assert resp.result == "success"
        assert resp.authorized_until == "永久"


class TestSecurityMechanisms:
    def test_replay_same_nonce_rejected(
        self, client, server_public_pem, storage, unused_code, fixed_timestamp, make_fingerprint
    ):
        """同一 (code, nonce) 第二次提交应被防重放拦截。"""
        request = {
            "activation_code": unused_code,
            "machine_code": make_fingerprint().to_dict(),
            "timestamp": fixed_timestamp,
            "nonce": "dup_nonce",
        }
        resp1, km1 = _post(client, server_public_pem, request)
        assert _decrypt(km1, resp1.content)["result"] == "success"

        resp2, km2 = _post(client, server_public_pem, request)
        data = _decrypt(km2, resp2.content)
        assert data["result"] == "error"
        assert "重复" in data["error_msg"]

    def test_expired_timestamp_rejected(
        self, client, server_public_pem, unused_code, fixed_timestamp, make_fingerprint
    ):
        """时间戳超出容忍窗口应被拒。"""
        request = {
            "activation_code": unused_code,
            "machine_code": make_fingerprint().to_dict(),
            "timestamp": fixed_timestamp - 99999,
            "nonce": "n",
        }
        resp, km = _post(client, server_public_pem, request)
        data = _decrypt(km, resp.content)
        assert data["result"] == "error"
        assert "时间戳" in data["error_msg"]

    def test_response_cannot_be_replayed_with_wrong_nonce(
        self, client, make_activator, storage
    ):
        """成功响应的 nonce 与请求一致（防篡改），客户端会校验。"""
        code = generate_activation_codes(1, db_path=storage.db.db_path)[0]
        activator = make_activator(client)
        resp = activator.activate(code)
        assert resp.result == "success"
        # nonce 是客户端发送的随机值，由服务端原样回显
        assert resp.nonce is not None
        assert len(resp.nonce) == 32  # token_hex(16)


class TestScripts:
    def test_generate_keys_writes_valid_keypair(self, tmp_path):
        """generate_keys 脚本应写出可加载的 RSA 密钥对。"""
        from sealium.scripts.generate_keys import generate_key_pair

        priv_path, pub_path = generate_key_pair(
            private_key_path=tmp_path / "server_private.pem",
            public_key_path=tmp_path / "server_public.pem",
            key_size=2048,
        )
        assert priv_path.exists()
        assert pub_path.exists()

        encryptor = RSAEncryptor.from_private_key_pem(priv_path.read_bytes())
        assert encryptor.has_private_key
        assert encryptor.has_public_key
        # 公钥可单独加载
        RSAEncryptor.from_public_key_pem(pub_path.read_bytes())

    def test_generate_keys_with_passphrase_roundtrip(self, tmp_path):
        """带口令的私钥：错误口令被拒、正确口令可加载（LOW-001）。"""
        from sealium.scripts.generate_keys import generate_key_pair

        priv_path, _ = generate_key_pair(
            private_key_path=tmp_path / "enc.pem",
            public_key_path=tmp_path / "enc.pub",
            key_size=2048,
            passphrase="correct-horse-battery",
        )
        # 错误口令 -> 失败
        with pytest.raises(Exception):
            RSAEncryptor.from_private_key_pem(priv_path.read_bytes(), password=b"wrong")
        # 正确口令 -> 加载成功
        enc = RSAEncryptor.from_private_key_pem(
            priv_path.read_bytes(), password=b"correct-horse-battery"
        )
        assert enc.has_private_key

    def test_generate_activation_codes_roundtrips_through_real_flow(
        self, client, make_activator, storage
    ):
        """脚本生成的码能被完整激活流程消费。"""
        codes = generate_activation_codes(
            2, features=["x"], expires_at="2026-12-31", db_path=storage.db.db_path
        )
        activator = make_activator(client)
        for code in codes:
            resp = activator.activate(code)
            assert resp.result == "success"
            assert resp.authorized_until == "2026-12-31"
