# test_symmetric_encryption.py
import unittest
import tempfile
from pathlib import Path
from sealium.utils.crypto import SymmetricEncryption

class TestSymmetricEncryption(unittest.TestCase):
    
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
        
    def test_encrypt_decrypt(self):
        """测试加密解密"""
        enc = SymmetricEncryption()
        enc.generate_key(set_this=True)
        
        message = "Hello, World! 你好世界！"
        encrypted = enc.encrypt(message)
        decrypted = enc.decrypt(encrypted)
        
        self.assertEqual(message, decrypted)
        self.assertNotEqual(message, encrypted)
        
    def test_save_and_load_key(self):
        """测试保存和加载密钥"""
        # 创建临时目录
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_key_path = Path(temp_dir) / "test.key"
            
            # 生成并保存
            enc1 = SymmetricEncryption()
            enc1.generate_key(set_this=True)
            enc1.save_key(temp_key_path)
            
            # 验证文件存在
            self.assertTrue(temp_key_path.exists())
            
            # 加载
            enc2 = SymmetricEncryption(temp_key_path)
            self.assertIsNotNone(enc2.cipher)
            
            # 验证密钥一致性
            message = "Test message"
            encrypted1 = enc1.encrypt(message)
            decrypted2 = enc2.decrypt(encrypted1)
            self.assertEqual(message, decrypted2)
        
    def test_invalid_key_path(self):
        """测试无效路径"""
        with self.assertRaises(FileNotFoundError):
            SymmetricEncryption("nonexistent.key")
            
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

if __name__ == '__main__':
    unittest.main()