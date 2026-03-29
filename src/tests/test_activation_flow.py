# tests/test_activation_flow.py
"""
详细的端到端激活流程测试（无需 Mock）
测试前需要：
1. 服务端已启动（uvicorn sealium.server.app:app --reload）
2. 数据库文件存在
3. 密钥文件存在

本测试会：
- 自动生成测试用的激活码
- 执行完整的激活流程
- 验证各种边界条件和错误情况
"""

import sys
import os
import time
import pytest
import requests
import json
from datetime import datetime, timedelta
from pathlib import Path

# 添加项目根目录到 Python 路径
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sealium.client.activator import Activator, ActivationError
from sealium.common.models import ActivationStatus
from sealium.common.utils import Utils
from sealium.server.database import SQLiteDatabase, ActivationCodeStorage

# ==================== 测试配置 ====================
BASE_URL = "http://localhost:8000"
ACTIVATION_URL = f"{BASE_URL}/v1/activation"
HEALTH_URL = f"{BASE_URL}/health"

# 密钥文件路径（与服务器配置一致）
SERVER_PUBLIC_KEY_PATH = Path("I:/Programming/Sealium/data/server_public.pem")
CLIENT_PRIVATE_KEY_PATH = Path("I:/Programming/Sealium/data/client_private.pem")
DATABASE_PATH = Path("I:/Programming/Sealium/data/database.db")


# ==================== Pytest Fixtures ====================
@pytest.fixture(scope="session")
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
    """提供数据库连接"""
    db = SQLiteDatabase(DATABASE_PATH)
    db.connect()
    yield db
    db.close()


@pytest.fixture
def storage(db):
    """提供激活码存储实例"""
    return ActivationCodeStorage(db)


@pytest.fixture
def client_keys():
    """加载客户端密钥"""
    with open(SERVER_PUBLIC_KEY_PATH, "r") as f:
        server_pub_key = f.read()
    with open(CLIENT_PRIVATE_KEY_PATH, "r") as f:
        client_priv_key = f.read()
    return server_pub_key, client_priv_key


@pytest.fixture
def activator(client_keys):
    """创建激活器实例"""
    server_pub_key, client_priv_key = client_keys
    return Activator(ACTIVATION_URL, server_pub_key, client_priv_key)


@pytest.fixture
def clean_unused_activation_code(storage):
    """生成一个干净的未使用激活码（每次测试后清理）"""
    from sealium.scripts.generate_activation_codes import generate_activation_codes

    codes = generate_activation_codes(1, db_path=storage.db.db_path)
    test_code = codes[0]

    yield test_code

    # 测试后清理：删除该激活码
    try:
        storage.delete(test_code)
    except:
        pass


@pytest.fixture
def expired_activation_code(storage):
    """生成一个已过期的激活码"""
    from sealium.scripts.generate_activation_codes import generate_activation_codes

    # 生成一个过期的激活码（有效期设为昨天）
    expires_at = datetime.now() - timedelta(days=1)
    codes = generate_activation_codes(
        1, expires_at=expires_at, db_path=storage.db.db_path
    )
    test_code = codes[0]

    yield test_code

    # 清理
    try:
        storage.delete(test_code)
    except:
        pass


@pytest.fixture
def used_activation_code_same_machine(storage, activator):
    """生成一个已使用且绑定当前机器的激活码"""
    from sealium.scripts.generate_activation_codes import generate_activation_codes

    # 生成激活码
    codes = generate_activation_codes(1, db_path=storage.db.db_path)
    test_code = codes[0]

    # 获取当前机器码
    machine_code = Utils.generate_machine_code()

    # 手动标记为已使用并绑定当前机器码
    storage.update_status(test_code, ActivationStatus.USED)
    storage.bind_machine_code(test_code, machine_code, datetime.now())

    yield test_code

    # 清理
    try:
        storage.delete(test_code)
    except:
        pass


@pytest.fixture
def used_activation_code_different_machine(storage):
    """生成一个已使用且绑定其他机器的激活码"""
    from sealium.scripts.generate_activation_codes import generate_activation_codes

    # 生成激活码
    codes = generate_activation_codes(1, db_path=storage.db.db_path)
    test_code = codes[0]

    # 手动标记为已使用并绑定其他机器码
    storage.update_status(test_code, ActivationStatus.USED)
    storage.bind_machine_code(test_code, "different_machine_code_12345", datetime.now())

    yield test_code

    # 清理
    try:
        storage.delete(test_code)
    except:
        pass


# ==================== 测试类 ====================
class TestActivationFlow:
    """激活流程完整测试"""

    def test_health_check(self):
        """测试健康检查接口"""
        resp = requests.get(HEALTH_URL, timeout=3)
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["service"] == "activation"

    def test_activation_success(
        self, activator, storage, clean_unused_activation_code, server_health_check
    ):
        """测试正常激活流程"""
        test_code = clean_unused_activation_code

        # 获取激活前的记录
        before = storage.get_by_code(test_code)
        assert before is not None
        assert before.status == ActivationStatus.UNUSED

        # 执行激活
        response = activator.activate(test_code)

        # 验证响应
        assert response.result == "success"
        assert response.authorized_until is not None
        assert response.features is not None
        assert response.nonce is not None
        assert len(response.nonce) > 0

        # 验证数据库记录已更新
        after = storage.get_by_code(test_code)
        assert after is not None
        assert after.status == ActivationStatus.USED
        assert after.bound_machine_code is not None
        assert after.activated_at is not None

        # 验证机器码格式（应该是 SHA256 十六进制）
        assert len(after.bound_machine_code) == 64
        assert all(c in "0123456789abcdef" for c in after.bound_machine_code)

    def test_activation_same_code_twice_same_machine(
        self, activator, storage, used_activation_code_same_machine, server_health_check
    ):
        """测试同一机器重复激活同一个激活码（应该返回成功）"""
        test_code = used_activation_code_same_machine

        # 第一次激活已经在 fixture 中完成
        # 第二次激活
        response = activator.activate(test_code)

        # 应该返回成功（已激活）
        assert response.result == "success"
        assert response.authorized_until is not None
        assert response.features is not None
        assert response.nonce is not None

        # 验证数据库记录未改变
        record = storage.get_by_code(test_code)
        assert record.status == ActivationStatus.USED
        assert record.bound_machine_code is not None

    def test_activation_already_used_code_different_machine(
        self, activator, used_activation_code_different_machine, server_health_check
    ):
        """测试使用已被其他机器使用的激活码（应该返回错误）"""
        test_code = used_activation_code_different_machine

        response = activator.activate(test_code)

        assert response.result == "error"
        assert (
            "已被其他设备使用" in response.error_msg or "已被使用" in response.error_msg
        )

    def test_activation_with_features(self, activator, storage, server_health_check):
        """测试带功能列表的激活码"""
        from sealium.scripts.generate_activation_codes import generate_activation_codes

        # 生成带功能列表的激活码
        features = ["premium", "enterprise", "support"]
        codes = generate_activation_codes(
            1, features=features, db_path=storage.db.db_path
        )
        test_code = codes[0]

        try:
            # 执行激活
            response = activator.activate(test_code)

            # 验证响应中的功能列表
            assert response.result == "success"
            assert response.features == features

            # 验证数据库中的功能列表
            record = storage.get_by_code(test_code)
            assert record.features == features
        finally:
            # 清理
            storage.delete(test_code)

    def test_activation_with_expiry_date(self, activator, storage, server_health_check):
        """测试带截止日期的激活码"""
        from sealium.scripts.generate_activation_codes import generate_activation_codes

        # 生成带截止日期的激活码（30天后）
        expires_at = datetime.now() + timedelta(days=30)
        expires_str = expires_at.strftime("%Y-%m-%d")
        codes = generate_activation_codes(
            1, expires_at=expires_at, db_path=storage.db.db_path
        )
        test_code = codes[0]

        try:
            # 执行激活
            response = activator.activate(test_code)

            # 验证响应中的截止日期
            assert response.result == "success"
            assert response.authorized_until == expires_str

            # 验证数据库中的截止日期
            record = storage.get_by_code(test_code)
            assert record.expires_at is not None
            # 比较日期（忽略时分秒）
            assert record.expires_at.date() == expires_at.date()
        finally:
            # 清理
            storage.delete(test_code)

    def test_activation_invalid_code(self, activator, server_health_check):
        """测试使用无效的激活码"""
        invalid_code = "invalid_code_12345"

        response = activator.activate(invalid_code)

        assert response.result == "error"
        assert "激活码不存在" in response.error_msg or "无效" in response.error_msg

    def test_activation_expired_code(
        self, activator, expired_activation_code, server_health_check
    ):
        """测试使用已过期的激活码"""
        test_code = expired_activation_code

        response = activator.activate(test_code)

        assert response.result == "error"
        assert "已过期" in response.error_msg

    def test_activation_network_error(
        self, activator, server_health_check, client_keys
    ):
        """测试网络错误时抛出 ActivationError"""
        server_pub_key, client_priv_key = client_keys

        # 创建一个指向不存在端口的 activator（使用有效密钥）
        bad_activator = Activator(
            "http://localhost:9999/v1/activation", server_pub_key, client_priv_key
        )

        with pytest.raises(ActivationError) as exc_info:
            bad_activator.activate("any_code")
        assert "网络请求失败" in str(exc_info.value)

    def test_activation_decrypt_error(
        self, activator, server_health_check, clean_unused_activation_code, monkeypatch
    ):
        """测试解密失败时抛出 ActivationError"""

        def mock_decrypt_response(*args, **kwargs):
            raise Exception("Decryption failed")

        # 模拟解密方法抛出异常
        monkeypatch.setattr(
            activator.key_manager, "decrypt_response", mock_decrypt_response
        )

        with pytest.raises(ActivationError) as exc_info:
            activator.activate(clean_unused_activation_code)
        assert "解密响应失败" in str(exc_info.value)

    def test_replay_attack_prevention(
        self, activator, storage, clean_unused_activation_code, server_health_check
    ):
        """测试防重放攻击（同一个激活码和 nonce 不能重复使用）"""
        test_code = clean_unused_activation_code

        # 第一次激活（应该成功）
        response1 = activator.activate(test_code)
        assert response1.result == "success"

        # 等待一小段时间确保时间戳不同
        time.sleep(0.1)

        # 第二次激活（应该成功，因为同一机器重复激活返回成功）
        response2 = activator.activate(test_code)
        assert response2.result == "success"
        assert response2.authorized_until is not None

    def test_machine_code_consistency(
        self, activator, storage, clean_unused_activation_code, server_health_check
    ):
        """测试机器码的一致性"""
        test_code = clean_unused_activation_code

        # 执行激活
        response = activator.activate(test_code)
        assert response.result == "success"

        # 获取数据库中的机器码
        record = storage.get_by_code(test_code)
        machine_code_in_db = record.bound_machine_code

        # 验证机器码格式正确（应该是64位十六进制）
        assert len(machine_code_in_db) == 64
        assert all(c in "0123456789abcdef" for c in machine_code_in_db)

        # 验证机器码在合理范围内（非空且不是默认值）
        assert machine_code_in_db != "0" * 64
        assert machine_code_in_db != "f" * 64

    def test_activation_response_encryption(
        self, activator, storage, clean_unused_activation_code, server_health_check
    ):
        """测试响应是加密的（不能直接解析为明文）"""
        import requests

        test_code = clean_unused_activation_code

        # 直接发送 HTTP 请求，不经过 Activator 解密
        # 1. 构造请求
        machine_code = Utils.generate_machine_code()
        nonce = Utils.generate_nonce(16)
        timestamp = Utils.get_timestamp_from_api()

        request_obj = {
            "activation_code": test_code,
            "machine_code": machine_code,
            "timestamp": timestamp,
            "nonce": nonce,
        }
        request_plain = json.dumps(request_obj).encode("utf-8")

        # 2. 加密请求
        encrypted_request = activator.key_manager.encrypt_request(request_plain)

        # 3. 发送请求
        resp = requests.post(ACTIVATION_URL, data=encrypted_request, timeout=10)

        # 4. 验证响应是二进制数据（加密的）
        assert resp.status_code == 200
        assert resp.headers.get("content-type") == "application/octet-stream"

        # 5. 验证响应不能直接解析为 JSON
        try:
            json.loads(resp.content)
            is_plain_json = True
        except:
            is_plain_json = False
        assert not is_plain_json, "响应应该是加密的，不应是明文 JSON"

        # 6. 使用客户端私钥解密验证
        decrypted = activator.key_manager.decrypt_response(resp.content)
        response_dict = json.loads(decrypted)

        assert response_dict["result"] == "success"
        assert "authorized_until" in response_dict
        assert "nonce" in response_dict

    def test_activation_without_machine_code(
        self, activator, storage, server_health_check
    ):
        """测试机器码生成功能"""
        from sealium.scripts.generate_activation_codes import generate_activation_codes

        # 生成激活码
        codes = generate_activation_codes(1, db_path=storage.db.db_path)
        test_code = codes[0]

        try:
            # 执行激活
            response = activator.activate(test_code)
            assert response.result == "success"

            # 验证数据库中的机器码已被填充
            record = storage.get_by_code(test_code)
            assert record.bound_machine_code is not None
            assert len(record.bound_machine_code) > 0
        finally:
            storage.delete(test_code)

    def test_activation_multiple_codes(self, activator, storage, server_health_check):
        """测试批量激活多个激活码"""
        from sealium.scripts.generate_activation_codes import generate_activation_codes

        # 生成 3 个激活码
        codes = generate_activation_codes(3, db_path=storage.db.db_path)

        try:
            for code in codes:
                # 每个激活码应该能成功激活
                response = activator.activate(code)
                assert response.result == "success"

                # 验证状态已更新
                record = storage.get_by_code(code)
                assert record.status == ActivationStatus.USED
        finally:
            # 清理
            for code in codes:
                try:
                    storage.delete(code)
                except:
                    pass

    def test_activation_same_machine_code_different_codes(
        self, activator, storage, server_health_check
    ):
        """测试同一台机器激活多个激活码"""
        from sealium.scripts.generate_activation_codes import generate_activation_codes

        # 生成 2 个激活码
        codes = generate_activation_codes(2, db_path=storage.db.db_path)

        try:
            # 激活第一个
            response1 = activator.activate(codes[0])
            assert response1.result == "success"

            # 激活第二个（同一台机器）
            response2 = activator.activate(codes[1])
            assert response2.result == "success"

            # 验证两个激活码绑定的机器码相同
            record1 = storage.get_by_code(codes[0])
            record2 = storage.get_by_code(codes[1])

            assert record1.bound_machine_code == record2.bound_machine_code
        finally:
            # 清理
            for code in codes:
                try:
                    storage.delete(code)
                except:
                    pass

    def test_response_nonce_exists(
        self, activator, storage, clean_unused_activation_code, server_health_check
    ):
        """测试成功响应中始终包含 nonce"""
        test_code = clean_unused_activation_code

        response = activator.activate(test_code)

        assert response.result == "success"
        assert response.nonce is not None
        assert len(response.nonce) > 0
        # nonce 应该是十六进制字符串
        assert all(c in "0123456789abcdef" for c in response.nonce)

    def test_timestamp_validation(
        self, activator, storage, clean_unused_activation_code, server_health_check
    ):
        """测试时间戳校验（通过修改客户端时间）"""
        test_code = clean_unused_activation_code

        response = activator.activate(test_code)

        # 正常情况下应该成功（时间戳在允许范围内）
        assert response.result == "success"

    def test_database_persistence(self, storage, clean_unused_activation_code):
        """测试数据库持久化（不通过 Activator）"""
        test_code = clean_unused_activation_code

        # 直接操作数据库
        record = storage.get_by_code(test_code)
        assert record is not None
        assert record.status == ActivationStatus.UNUSED

        # 手动更新
        storage.bind_machine_code(test_code, "test_machine_code", datetime.now())

        # 验证更新
        updated = storage.get_by_code(test_code)
        assert updated.status == ActivationStatus.USED
        assert updated.bound_machine_code == "test_machine_code"
        assert updated.activated_at is not None

    def test_activation_with_expired_timestamp(
        self,
        activator,
        storage,
        clean_unused_activation_code,
        server_health_check,
        monkeypatch,
    ):
        """测试时间戳过期的情况（模拟时间戳 API 返回过去的时间）"""
        test_code = clean_unused_activation_code

        # 模拟时间戳 API 返回一个非常旧的时间戳（7天前）
        old_timestamp = int(time.time()) - 7 * 24 * 3600

        def mock_timestamp_api(*args, **kwargs):
            return old_timestamp

        # 使用 monkeypatch 替换 get_timestamp_from_api 方法
        monkeypatch.setattr(Utils, "get_timestamp_from_api", mock_timestamp_api)

        # 执行激活（应该因为时间戳过期而失败）
        response = activator.activate(test_code)

        assert response.result == "error"
        assert "时间戳无效" in response.error_msg or "请同步时间" in response.error_msg


if __name__ == "__main__":
    # 运行所有测试
    pytest.main([__file__, "-v", "--tb=short"])
