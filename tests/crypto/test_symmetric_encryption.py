# test_symmetric_encryption.py
import unittest
import tempfile
import os
from pathlib import Path
from cryptography.fernet import Fernet
from sealium.utils.crypto import SymmetricEncryption

class TestSymmetricEncryption(unittest.TestCase):
    
    def test_init_with_none_key_path(self):
        """测试使用 None 初始化"""
        enc = SymmetricEncryption()
        self.assertIsNone(enc.key_path)
        self.assertIsNone(enc.cipher)
        self.assertIsNone(enc.key_data)
        
    def test_init_with_string_key_path(self):
        """测试使用字符串路径初始化"""
        # 创建有效的 Fernet 密钥
        key = Fernet.generate_key().decode('utf-8')
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.key') as f:
            f.write(key)
            temp_path = f.name
            
        try:
            enc = SymmetricEncryption(temp_path)
            self.assertIsInstance(enc.key_path, Path)
            self.assertEqual(str(enc.key_path), temp_path)
            # 验证密钥已成功加载
            self.assertIsNotNone(enc.cipher)
        finally:
            os.unlink(temp_path)
            
    def test_init_with_path_key_path(self):
        """测试使用 Path 对象初始化"""
        # 创建有效的 Fernet 密钥
        key = Fernet.generate_key().decode('utf-8')
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.key') as f:
            f.write(key)
            temp_path = f.name
            
        try:
            path_obj = Path(temp_path)
            enc = SymmetricEncryption(path_obj)
            self.assertEqual(enc.key_path, path_obj)
            # 验证密钥已成功加载
            self.assertIsNotNone(enc.cipher)
        finally:
            os.unlink(temp_path)
            
    def test_init_with_invalid_type(self):
        """测试使用无效类型初始化"""
        with self.assertRaises(TypeError):
            SymmetricEncryption(123)
            
    def test_init_with_nonexistent_file(self):
        """测试初始化时文件不存在"""
        with self.assertRaises(FileNotFoundError):
            SymmetricEncryption("nonexistent.key")
            
    def test_init_with_directory(self):
        """测试初始化时路径是目录"""
        with tempfile.TemporaryDirectory() as temp_dir:
            with self.assertRaises(ValueError):
                SymmetricEncryption(temp_dir)
                
    def test_init_with_invalid_key_format(self):
        """测试初始化时使用无效的密钥格式"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.key') as f:
            f.write("invalid_key_format")
            temp_path = f.name
            
        try:
            with self.assertRaises(ValueError) as context:
                SymmetricEncryption(temp_path)
            self.assertIn("Failed to load or parse symmetric key", str(context.exception))
        finally:
            os.unlink(temp_path)
                
    def test_generate_key(self):
        """测试密钥生成"""
        enc = SymmetricEncryption()
        key = enc.generate_key()
        
        self.assertIsInstance(key, str)
        self.assertGreater(len(key), 30)
        
    def test_generate_key_set_this(self):
        """测试生成密钥并设置"""
        enc = SymmetricEncryption()
        key = enc.generate_key(set_this=True)
        
        self.assertIsNotNone(enc.key_data)
        self.assertIsNotNone(enc.cipher)
        self.assertEqual(enc.key_data, key)
        
    def test_save_key(self):
        """测试保存密钥"""
        enc = SymmetricEncryption()
        key = enc.generate_key(set_this=True)
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.key') as f:
            temp_path = f.name
            
        try:
            enc.save_key(temp_path)
            
            # 验证文件内容
            with open(temp_path, 'r') as f:
                saved_key = f.read()
            self.assertEqual(saved_key, key)
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
                
    def test_save_key_without_key_data(self):
        """测试在没有密钥数据时保存密钥"""
        enc = SymmetricEncryption()
        with tempfile.NamedTemporaryFile(delete=False, suffix='.key') as f:
            temp_path = f.name
            
        try:
            with self.assertRaises(TypeError):  # write_text() 不能接受 None
                enc.save_key(temp_path)
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
                
    def test_encrypt_decrypt(self):
        """测试加密解密功能"""
        enc = SymmetricEncryption()
        enc.generate_key(set_this=True)
        
        message = "Hello, World! 你好世界！"
        encrypted = enc.encrypt(message)
        decrypted = enc.decrypt(encrypted)
        
        self.assertEqual(message, decrypted)
        self.assertNotEqual(message, encrypted)
        self.assertIsInstance(encrypted, str)
        
    def test_encrypt_without_key(self):
        """测试没有密钥时加密"""
        enc = SymmetricEncryption()
        with self.assertRaises(ValueError) as context:
            enc.encrypt("test message")
        self.assertIn("Symmetric key not loaded", str(context.exception))
        
    def test_decrypt_without_key(self):
        """测试没有密钥时解密"""
        enc = SymmetricEncryption()
        with self.assertRaises(ValueError) as context:
            enc.decrypt("fake_encrypted_data")
        self.assertIn("Symmetric key not loaded", str(context.exception))
        
    def test_decrypt_with_invalid_token(self):
        """测试解密无效令牌"""
        enc = SymmetricEncryption()
        enc.generate_key(set_this=True)
        
        with self.assertRaises(ValueError) as context:
            enc.decrypt("invalid_base64_data")
        self.assertIn("Decryption failed", str(context.exception))
        
    def test_full_workflow(self):
        """测试完整工作流程"""
        with tempfile.TemporaryDirectory() as temp_dir:
            key_path = Path(temp_dir) / "test.key"
            
            # 1. 生成密钥并保存
            enc1 = SymmetricEncryption()
            enc1.generate_key(set_this=True)
            enc1.save_key(key_path)
            
            # 2. 从文件加载密钥
            enc2 = SymmetricEncryption(key_path)
            
            # 3. 测试加密解密
            message = "Test message for full workflow"
            encrypted = enc2.encrypt(message)
            decrypted = enc2.decrypt(encrypted)
            
            self.assertEqual(message, decrypted)
            
    def test_encrypt_non_ascii_characters(self):
        """测试加密非ASCII字符"""
        enc = SymmetricEncryption()
        enc.generate_key(set_this=True)
        
        message = "Hello 世界 🌍 Привет こんにちは"
        encrypted = enc.encrypt(message)
        decrypted = enc.decrypt(encrypted)
        
        self.assertEqual(message, decrypted)
        
    def test_encrypt_empty_string(self):
        """测试加密空字符串"""
        enc = SymmetricEncryption()
        enc.generate_key(set_this=True)
        
        message = ""
        encrypted = enc.encrypt(message)
        decrypted = enc.decrypt(encrypted)
        
        self.assertEqual(message, decrypted)

if __name__ == '__main__':
    unittest.main()