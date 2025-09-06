# test_asymmetric_encryption.py
import unittest
import tempfile
import os
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from sealium.utils.crypto import AsymmetricEncryption

class TestAsymmetricEncryption(unittest.TestCase):
    
    def _create_valid_temp_rsa_keys(self):
        """创建有效的临时RSA密钥对文件"""
        # 生成密钥对
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()
        
        # 创建临时目录
        temp_dir = tempfile.mkdtemp()
        pub_path = Path(temp_dir) / "public.pub"
        priv_path = Path(temp_dir) / "private.key"
        
        # 序列化并保存公钥
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        pub_path.write_bytes(public_pem)
        
        # 序列化并保存私钥
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        priv_path.write_bytes(private_pem)
        
        return str(pub_path), str(priv_path), temp_dir
    
    def test_init_with_none_paths(self):
        """测试使用 None 路径初始化"""
        enc = AsymmetricEncryption()
        self.assertIsNone(enc.public_key_path)
        self.assertIsNone(enc.private_key_path)
        self.assertIsNone(enc.public_key)
        self.assertIsNone(enc.private_key)
        
    def test_init_with_string_paths(self):
        """测试使用字符串路径初始化"""
        pub_path, priv_path, temp_dir = self._create_valid_temp_rsa_keys()
        
        try:
            enc = AsymmetricEncryption(pub_path, priv_path)
            self.assertIsInstance(enc.public_key_path, Path)
            self.assertIsInstance(enc.private_key_path, Path)
            self.assertEqual(str(enc.public_key_path), pub_path)
            self.assertEqual(str(enc.private_key_path), priv_path)
            # 验证密钥已成功加载
            self.assertIsNotNone(enc.public_key)
            self.assertIsNotNone(enc.private_key)
        finally:
            # 清理临时文件
            import shutil
            shutil.rmtree(temp_dir)
            
    def test_init_with_path_objects(self):
        """测试使用 Path 对象初始化"""
        pub_path, priv_path, temp_dir = self._create_valid_temp_rsa_keys()
        
        try:
            pub_path_obj = Path(pub_path)
            priv_path_obj = Path(priv_path)
            enc = AsymmetricEncryption(pub_path_obj, priv_path_obj)
            self.assertEqual(enc.public_key_path, pub_path_obj)
            self.assertEqual(enc.private_key_path, priv_path_obj)
            # 验证密钥已成功加载
            self.assertIsNotNone(enc.public_key)
            self.assertIsNotNone(enc.private_key)
        finally:
            # 清理临时文件
            import shutil
            shutil.rmtree(temp_dir)
            
    def test_init_with_invalid_public_key_type(self):
        """测试使用无效的公钥路径类型"""
        with self.assertRaises(TypeError):
            AsymmetricEncryption(123, None)
            
    def test_init_with_invalid_private_key_type(self):
        """测试使用无效的私钥路径类型"""
        with self.assertRaises(TypeError):
            AsymmetricEncryption(None, 123)
            
    def test_init_with_nonexistent_public_key_file(self):
        """测试初始化时公钥文件不存在"""
        with self.assertRaises(FileNotFoundError):
            AsymmetricEncryption("nonexistent.pub", None)
            
    def test_init_with_nonexistent_private_key_file(self):
        """测试初始化时私钥文件不存在"""
        pub_path, priv_path, temp_dir = self._create_valid_temp_rsa_keys()
        
        try:
            # 确保私钥文件不存在
            os.unlink(priv_path)  # 删除私钥文件
            nonexistent_priv_path = "nonexistent.key"
            
            with self.assertRaises(FileNotFoundError) as context:
                AsymmetricEncryption(pub_path, nonexistent_priv_path)
            self.assertIn("Private key file not found", str(context.exception))
        finally:
            # 清理临时文件
            import shutil
            shutil.rmtree(temp_dir)
            
    def test_init_with_directory_paths(self):
        """测试初始化时路径是目录"""
        with tempfile.TemporaryDirectory() as temp_dir:
            dir_path = Path(temp_dir)
            with self.assertRaises(ValueError):
                AsymmetricEncryption(dir_path, None)
                
    def test_init_with_invalid_pem_files(self):
        """测试初始化时使用无效的PEM文件"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.pub') as pub_f, \
             tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.key') as priv_f:
            pub_f.write("invalid pem content")
            priv_f.write("invalid pem content")
            pub_path = pub_f.name
            priv_path = priv_f.name
            
        try:
            with self.assertRaises(ValueError) as context:
                AsymmetricEncryption(pub_path, priv_path)
            # 验证错误信息中包含PEM相关的内容
            self.assertIn("Failed to load public key", str(context.exception))
        finally:
            os.unlink(pub_path)
            os.unlink(priv_path)
                
    def test_generate_keys(self):
        """测试密钥生成"""
        enc = AsymmetricEncryption()
        private_key, public_key = enc.generate_keys()
        
        self.assertIsNotNone(private_key)
        self.assertIsNotNone(public_key)
        # 检查返回的密钥类型
        from cryptography.hazmat.primitives.asymmetric import rsa
        self.assertIsInstance(private_key, rsa.RSAPrivateKey)
        self.assertIsInstance(public_key, rsa.RSAPublicKey)
        
    def test_generate_keys_with_invalid_size(self):
        """测试使用无效密钥大小生成密钥"""
        enc = AsymmetricEncryption()
        with self.assertRaises(ValueError):
            enc.generate_keys(key_size=256)  # 太小
            
    def test_generate_keys_set_this(self):
        """测试生成密钥并设置到实例"""
        enc = AsymmetricEncryption()
        private_key, public_key = enc.generate_keys(set_this=True)
        
        self.assertIsNotNone(enc.private_key)
        self.assertIsNotNone(enc.public_key)
        self.assertEqual(enc.private_key, private_key)
        self.assertEqual(enc.public_key, public_key)
        
    def test_generate_keys_default_size(self):
        """测试默认密钥大小"""
        enc = AsymmetricEncryption()
        private_key, public_key = enc.generate_keys()
        
        # 检查密钥大小
        self.assertEqual(private_key.key_size, 2048)
        self.assertEqual(public_key.key_size, 2048)
        
    def test_encrypt_without_public_key(self):
        """测试没有公钥时加密"""
        enc = AsymmetricEncryption()
        with self.assertRaises(ValueError) as context:
            enc.encrypt("test message")
        self.assertIn("Public key not loaded", str(context.exception))
        
    def test_decrypt_without_private_key(self):
        """测试没有私钥时解密"""
        enc = AsymmetricEncryption()
        with self.assertRaises(ValueError) as context:
            enc.decrypt("fake_encrypted_data")
        self.assertIn("Private key not loaded", str(context.exception))
        
    def test_encrypt_decrypt_workflow(self):
        """测试加密解密完整工作流程"""
        enc = AsymmetricEncryption()
        enc.generate_keys(set_this=True)
        
        message = "Hello, World! 你好世界！"
        encrypted = enc.encrypt(message)
        decrypted = enc.decrypt(encrypted)
        
        self.assertEqual(message, decrypted)
        self.assertNotEqual(message, encrypted)
        self.assertIsInstance(encrypted, str)
        
    def test_encrypt_non_ascii_characters(self):
        """测试加密非ASCII字符"""
        enc = AsymmetricEncryption()
        enc.generate_keys(set_this=True)
        
        message = "Hello 世界 🌍 Привет こんにちは"
        encrypted = enc.encrypt(message)
        decrypted = enc.decrypt(encrypted)
        
        self.assertEqual(message, decrypted)
        
    def test_encrypt_empty_string(self):
        """测试加密空字符串"""
        enc = AsymmetricEncryption()
        enc.generate_keys(set_this=True)
        
        message = ""
        encrypted = enc.encrypt(message)
        decrypted = enc.decrypt(encrypted)
        
        self.assertEqual(message, decrypted)
        
    def test_save_keys_without_generated_keys(self):
        """测试在没有生成密钥时保存密钥"""
        enc = AsymmetricEncryption()
        with tempfile.TemporaryDirectory() as temp_dir:
            pub_path = Path(temp_dir) / "public.pub"
            priv_path = Path(temp_dir) / "private.key"
            
            with self.assertRaises(ValueError) as context:
                enc.save_keys(pub_path, priv_path)
            self.assertIn("Keys have not been generated yet", str(context.exception))
                
    def test_full_workflow_with_key_generation_and_saving(self):
        """测试完整的密钥生成、保存、加载、使用流程"""
        with tempfile.TemporaryDirectory() as temp_dir:
            pub_path = Path(temp_dir) / "public.pub"
            priv_path = Path(temp_dir) / "private.key"
            
            # 1. 生成密钥
            enc1 = AsymmetricEncryption()
            enc1.generate_keys(set_this=True)
            
            # 2. 保存密钥
            enc1.save_keys(pub_path, priv_path)
            
            # 3. 验证文件存在
            self.assertTrue(pub_path.exists())
            self.assertTrue(priv_path.exists())
            
            # 4. 从文件加载密钥
            enc2 = AsymmetricEncryption(pub_path, priv_path)
            self.assertIsNotNone(enc2.public_key)
            self.assertIsNotNone(enc2.private_key)
            
            # 5. 测试加密解密
            message = "Test message for full workflow"
            encrypted = enc2.encrypt(message)
            decrypted = enc2.decrypt(encrypted)
            
            self.assertEqual(message, decrypted)
            
    def test_validate_path_nonexistent(self):
        """测试验证不存在的路径"""
        enc = AsymmetricEncryption()
        with self.assertRaises(FileNotFoundError):
            enc._validate_path(Path("nonexistent.file"), "Test file")
            
    def test_validate_path_directory(self):
        """测试验证目录路径"""
        with tempfile.TemporaryDirectory() as temp_dir:
            enc = AsymmetricEncryption()
            dir_path = Path(temp_dir)
            with self.assertRaises(ValueError):
                enc._validate_path(dir_path, "Test file")

if __name__ == '__main__':
    unittest.main()