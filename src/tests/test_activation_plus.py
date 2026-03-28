# tests/test_activation_plus.py
"""
更深入的激活系统测试（依赖真实服务端，使用主数据库）
测试前需要：
1. 服务端已启动（uvicorn sealium.server.app:app --reload）
2. 数据库文件存在
3. 密钥文件存在
"""

import sys
import os
import time
import json
import pytest
import requests
import threading
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

# 添加项目根目录到 Python 路径
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sealium.client.activator import Activator, ActivationError
from sealium.common.models import ActivationStatus
from sealium.common.utils import Utils
from sealium.server.database import SQLiteDatabase, ActivationCodeStorage
from sealium.server.config import config
from sealium.scripts.generate_activation_codes import generate_activation_codes

# 针对 Windows 线程中调用 wmi 需要初始化 COM
if sys.platform == "win32":
        import pythoncom

# ==================== 测试配置 ====================
BASE_URL = "http://localhost:8000"
ACTIVATION_URL = f"{BASE_URL}/v1/activation"
HEALTH_URL = f"{BASE_URL}/health"

# 项目根目录（自动检测）
PROJECT_ROOT = Path(__file__).resolve().parents[2]  # 从 tests/ 到项目根目录

# 使用主数据库（服务端实际使用的数据库）
DATABASE_PATH = config.DATABASE_PATH

# 密钥文件路径（优先从 data 目录读取，与数据库同目录）
SERVER_PUBLIC_KEY_PATH = PROJECT_ROOT / "data" / "server_public.pem"
CLIENT_PRIVATE_KEY_PATH = PROJECT_ROOT / "data" / "client_private.pem"

# 如果 data 目录下不存在，尝试 certs 目录（兼容旧结构）
if not SERVER_PUBLIC_KEY_PATH.exists():
        SERVER_PUBLIC_KEY_PATH = PROJECT_ROOT / "certs" / "server_public.pem"
if not CLIENT_PRIVATE_KEY_PATH.exists():
        CLIENT_PRIVATE_KEY_PATH = PROJECT_ROOT / "certs" / "client_private.pem"


# ==================== Fixtures ====================
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
def storage():
        """使用主数据库的存储实例"""
        db = SQLiteDatabase(str(DATABASE_PATH))
        db.connect()
        yield ActivationCodeStorage(db)
        db.close()


@pytest.fixture
def client_keys():
        """加载客户端密钥"""
        if not SERVER_PUBLIC_KEY_PATH.exists():
                pytest.skip(f"服务端公钥文件不存在: {SERVER_PUBLIC_KEY_PATH}")
        if not CLIENT_PRIVATE_KEY_PATH.exists():
                pytest.skip(f"客户端私钥文件不存在: {CLIENT_PRIVATE_KEY_PATH}")
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
        """生成一个干净的未使用激活码（使用主数据库，测试后清理）"""
        codes = generate_activation_codes(1, db_path=DATABASE_PATH)
        test_code = codes[0]
        yield test_code
        # 测试后清理
        storage.delete(test_code)


@pytest.fixture
def used_activation_code_same_machine(storage):
        """生成一个已使用且绑定当前机器的激活码"""
        codes = generate_activation_codes(1, db_path=DATABASE_PATH)
        test_code = codes[0]
        machine_code = Utils.generate_machine_code()
        storage.update_status(test_code, ActivationStatus.USED)
        storage.bind_machine_code(test_code, machine_code, datetime.now())
        yield test_code
        storage.delete(test_code)


@pytest.fixture
def used_activation_code_different_machine(storage):
        """生成一个已使用且绑定其他机器的激活码"""
        codes = generate_activation_codes(1, db_path=DATABASE_PATH)
        test_code = codes[0]
        storage.update_status(test_code, ActivationStatus.USED)
        storage.bind_machine_code(test_code, "different_machine_code", datetime.now())
        yield test_code
        storage.delete(test_code)


@pytest.fixture
def expired_activation_code(storage):
        """生成一个已过期的激活码"""
        expires_at = datetime.now() - timedelta(days=1)
        codes = generate_activation_codes(1, expires_at=expires_at, db_path=DATABASE_PATH)
        test_code = codes[0]
        yield test_code
        storage.delete(test_code)


# ==================== 边界条件测试 ====================
class TestBoundaryConditions:
        """边界条件测试"""

        def test_timestamp_boundary(self, activator, storage, clean_unused_activation_code, monkeypatch):
                """时间戳边界测试 - 验证300秒容忍度"""
                real_timestamp = Utils.get_timestamp_from_api()
                tolerance = config.TIME_STAMP_TOLERANCE_SECONDS  # 300

                original_timestamp = Utils.get_timestamp_from_api

                # 测试边界值（成功）
                for delta in [-tolerance, tolerance]:
                        codes = generate_activation_codes(1, db_path=DATABASE_PATH)
                        test_code = codes[0]
                        mock_timestamp = real_timestamp + delta

                        monkeypatch.setattr(Utils, "get_timestamp_from_api", lambda timeout=None: mock_timestamp)
                        response = activator.activate(test_code)
                        assert response.result == "success", f"delta={delta} 应该成功"
                        storage.delete(test_code)

                # 恢复原始方法
                monkeypatch.setattr(Utils, "get_timestamp_from_api", original_timestamp)

                # 测试超出容忍度的值（使用 tolerance + 60，确保失败）
                codes = generate_activation_codes(1, db_path=DATABASE_PATH)
                test_code = codes[0]
                mock_timestamp = real_timestamp + tolerance + 60
                monkeypatch.setattr(Utils, "get_timestamp_from_api", lambda timeout=None: mock_timestamp)

                response = activator.activate(test_code)
                assert response.result == "error", f"偏移量 {tolerance + 60} 秒应该失败"
                assert "时间戳无效" in response.error_msg or "请同步时间" in response.error_msg

                storage.delete(test_code)
                monkeypatch.setattr(Utils, "get_timestamp_from_api", original_timestamp)

        def test_activation_code_length_boundary(self, activator):
                """激活码长度边界测试"""
                response = activator.activate("")
                assert response.result == "error"
                assert "无效" in response.error_msg or "不存在" in response.error_msg

                long_code = "a" * 100
                response = activator.activate(long_code)
                assert response.result == "error"
                assert "不存在" in response.error_msg

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

                codes = generate_activation_codes(1, db_path=DATABASE_PATH)
                test_code2 = codes[0]
                response2 = activator.activate(test_code2)
                assert response2.result == "success"
                record2 = storage.get_by_code(test_code2)
                machine2 = record2.bound_machine_code
                assert machine1 == machine2
                storage.delete(test_code2)


# ==================== 异常场景测试（Mock 客户端） ====================
class TestExceptionScenarios:
        """异常场景测试 - 使用 monkeypatch 模拟异常情况"""

        def test_database_connection_failure(self):
                pytest.skip("需要在服务端单元测试中模拟数据库失败")

        def test_corrupted_private_key(self, client_keys):
                server_pub_key, _ = client_keys
                with pytest.raises(ValueError) as exc:
                        Activator(ACTIVATION_URL, server_pub_key, "invalid key")
                assert "PEM" in str(exc.value) or "load" in str(exc.value)

        def test_server_returns_malformed_response(self, activator, clean_unused_activation_code, monkeypatch):
                def mock_post(*args, **kwargs):
                        resp = requests.Response()
                        resp._content = b"this is not encrypted"
                        resp.status_code = 200
                        return resp

                monkeypatch.setattr(requests, "post", mock_post)
                with pytest.raises(ActivationError) as exc:
                        activator.activate(clean_unused_activation_code)
                assert "解密响应失败" in str(exc.value)

        def test_server_returns_empty_response(self, activator, clean_unused_activation_code, monkeypatch):
                def mock_post(*args, **kwargs):
                        resp = requests.Response()
                        resp._content = b""
                        resp.status_code = 200
                        return resp

                monkeypatch.setattr(requests, "post", mock_post)
                with pytest.raises(ActivationError) as exc:
                        activator.activate(clean_unused_activation_code)
                assert "解密响应失败" in str(exc.value)

        def test_encryption_payload_overflow(self, activator, monkeypatch):
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
                """并发激活同一个激活码，所有请求都应成功（同一机器幂等性）"""
                test_code = clean_unused_activation_code
                results = []
                errors = []

                def worker():
                        # 在 Windows 线程中初始化 COM
                        if sys.platform == "win32":
                                pythoncom.CoInitialize()
                        try:
                                resp = activator.activate(test_code)
                                results.append(resp.result)
                        except Exception as e:
                                errors.append(str(e))
                                results.append("exception")
                        finally:
                                if sys.platform == "win32":
                                        pythoncom.CoUninitialize()

                threads = [threading.Thread(target=worker) for _ in range(10)]
                for t in threads:
                        t.start()
                for t in threads:
                        t.join()

                # 打印错误信息以便调试
                if errors:
                        print(f"Errors occurred: {errors[:3]}")

                success_count = results.count("success")
                # 所有请求都应该成功（同一机器重复激活返回成功）
                assert success_count == 10, f"Expected 10 successes, got {success_count}, results: {results[:5]}"

                # 验证数据库状态
                record = storage.get_by_code(test_code)
                assert record is not None
                assert record.status == ActivationStatus.USED

        def test_concurrent_activation_different_machine(self, activator, storage):
                """并发激活同一个激活码，只有一个应成功（模拟不同机器）"""
                # 生成激活码
                codes = generate_activation_codes(1, db_path=DATABASE_PATH)
                test_code = codes[0]
                results = []
                errors = []
                machine_counter = 0

                def worker(machine_id):
                        # 在 Windows 线程中初始化 COM
                        if sys.platform == "win32":
                                pythoncom.CoInitialize()
                        nonlocal machine_counter
                        machine_counter += 1
                        mock_machine = f"mock_machine_{machine_counter}"
                        try:
                                with patch("sealium.common.utils.Utils.generate_machine_code",
                                           return_value=mock_machine):
                                        resp = activator.activate(test_code)
                                        results.append(resp.result)
                        except Exception as e:
                                errors.append(str(e))
                                results.append("exception")
                        finally:
                                if sys.platform == "win32":
                                        pythoncom.CoUninitialize()

                threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
                for t in threads:
                        t.start()
                for t in threads:
                        t.join()

                # 打印错误信息以便调试
                if errors:
                        print(f"Errors occurred: {errors[:3]}")

                success_count = results.count("success")
                # 只有一个成功，其余应失败
                assert success_count == 1, f"Expected 1 success, got {success_count}, results: {results}"

                # 验证数据库状态
                record = storage.get_by_code(test_code)
                assert record is not None
                assert record.status == ActivationStatus.USED

                # 清理
                storage.delete(test_code)

        def test_concurrent_generate_activation_codes(self, storage):
                """并发生成激活码，确保唯一性"""
                codes_list = []

                def worker():
                        codes = generate_activation_codes(100, db_path=DATABASE_PATH)
                        codes_list.extend(codes)

                threads = [threading.Thread(target=worker) for _ in range(5)]
                for t in threads:
                        t.start()
                for t in threads:
                        t.join()

                # 验证所有激活码唯一
                assert len(set(codes_list)) == len(codes_list), f"Duplicate codes found"
                # 验证数据库中的记录数
                all_codes = storage.list_all()
                # 注意：这里可能有其他测试生成的激活码，所以只检查新生成的
                codes_in_db = [c.activation_code for c in all_codes if c.activation_code in codes_list]
                assert len(codes_in_db) == len(codes_list), f"Missing codes in database"

                # 清理
                for code in codes_list:
                        storage.delete(code)


# ==================== 安全测试 ====================
class TestSecurity:
        """安全攻击测试"""

        def test_replay_attack_with_different_nonce(self, activator, storage, clean_unused_activation_code):
                """同一机器重复激活应成功"""
                test_code = clean_unused_activation_code
                resp1 = activator.activate(test_code)
                assert resp1.result == "success"
                resp2 = activator.activate(test_code)
                assert resp2.result == "success"
                assert resp2.authorized_until == resp1.authorized_until

        def test_replay_attack_different_machine(self, activator, storage, used_activation_code_different_machine):
                """已用于其他机器的激活码，无法激活"""
                test_code = used_activation_code_different_machine
                response = activator.activate(test_code)
                assert response.result == "error"
                assert "已被使用" in response.error_msg or "已被其他设备使用" in response.error_msg

        def test_tamper_encrypted_request(self, activator):
                """篡改加密请求数据，应导致解密失败"""
                random_data = os.urandom(100)
                resp = requests.post(ACTIVATION_URL, data=random_data, timeout=10)
                try:
                        activator.key_manager.decrypt_response(resp.content)
                        assert False, "应该解密失败"
                except Exception:
                        pass

        def test_expired_activation_code(self, activator, expired_activation_code):
                """过期激活码无法激活"""
                response = activator.activate(expired_activation_code)
                assert response.result == "error"
                assert "已过期" in response.error_msg or "不存在" in response.error_msg


# ==================== 数据一致性测试 ====================
class TestDataConsistency:
        """数据一致性测试"""

        def test_activation_twice_different_machine(self, activator, storage, clean_unused_activation_code):
                """激活后，尝试使用同一激活码在不同机器激活（应失败）"""
                test_code = clean_unused_activation_code
                resp1 = activator.activate(test_code)
                assert resp1.result == "success"

                def mock_machine_code():
                        return "different_machine"

                with patch("sealium.common.utils.Utils.generate_machine_code", side_effect=mock_machine_code):
                        resp2 = activator.activate(test_code)
                        assert resp2.result == "error"
                        assert "已被使用" in resp2.error_msg or "已被其他设备使用" in resp2.error_msg

        def test_activation_code_uniqueness(self, storage):
                from sealium.common.models import ActivationCode
                code = "test_unique_code"
                activation = ActivationCode(activation_code=code, status=ActivationStatus.UNUSED)
                storage.create(activation)
                with pytest.raises(Exception) as exc:
                        storage.create(activation)
                assert "UNIQUE constraint failed" in str(exc.value)
                storage.delete(code)


# ==================== 服务端配置变更测试（跳过） ====================
class TestConfigChanges:
        def test_tolerance_change(self):
                pytest.skip("需要服务端支持动态配置")

        def test_private_key_reload(self):
                pytest.skip("需要服务端重启测试")


# ==================== 同一机器重复激活测试 ====================
class TestSameMachineReactivation:
        def test_same_machine_reactivation_success(self, activator, used_activation_code_same_machine):
                response = activator.activate(used_activation_code_same_machine)
                assert response.result == "success"
                assert response.authorized_until is not None

        def test_different_machine_activation_fails(self, activator, used_activation_code_different_machine):
                response = activator.activate(used_activation_code_different_machine)
                assert response.result == "error"
                assert "已被使用" in response.error_msg or "已被其他设备使用" in response.error_msg


if __name__ == "__main__":
        pytest.main([__file__, "-v", "--tb=short"])