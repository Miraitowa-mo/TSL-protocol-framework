from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP
import base64

class SimpleRSA:
    def __init__(self):
        self.private_key = None
        self.public_key = None

    def generate_keys(self, key_size=2048):
        """生成RSA密钥对"""
        key = RSA.generate(key_size)
        self.private_key = key
        self.public_key = key.publickey()
        return self.public_key

    def sign_message(self, message):
        """对消息进行签名"""
        if not self.private_key:
            raise ValueError("没有私钥，请先生成密钥对")

        # 创建消息的哈希
        message_hash = SHA256.new(message.encode('utf-8'))
        # 使用私钥签名
        signature = pkcs1_15.new(self.private_key).sign(message_hash)
        # 将签名转换为base64字符串便于传输
        return base64.b64encode(signature).decode('utf-8')

    def verify_signature(self, public_key, message, signature):
        """验证签名"""
        try:
            # 解码base64签名
            signature_bytes = base64.b64decode(signature)
            # 创建消息的哈希
            message_hash = SHA256.new(message.encode('utf-8'))
            # 使用公钥验证签名
            pkcs1_15.new(public_key).verify(message_hash, signature_bytes)
            return True
        except (ValueError, TypeError):
            return False

    def encrypt_message(self, public_key, message):
        """使用公钥加密消息"""
        cipher = PKCS1_OAEP.new(public_key)
        encrypted = cipher.encrypt(message.encode('utf-8'))
        return base64.b64encode(encrypted).decode('utf-8')

    def decrypt_message(self, encrypted_message):
        """使用私钥解密消息"""
        cipher = PKCS1_OAEP.new(self.private_key)
        encrypted_bytes = base64.b64decode(encrypted_message)
        decrypted = cipher.decrypt(encrypted_bytes)
        return decrypted.decode('utf-8')


# 导出公钥和导入公钥的辅助函数
def export_public_key(public_key):
    """将公钥导出为字符串"""
    return public_key.export_key().decode('utf-8')


def import_public_key(public_key_str):
    """从字符串导入公钥"""
    return RSA.import_key(public_key_str)

from Crypto.PublicKey import ECC

class SimpleECDH:
    def __init__(self):
        self.private_key = None
        self.public_key = None

    def generate_keys(self):
        """生成ECC密钥对"""
        self.private_key = ECC.generate(curve='P-256')
        self.public_key = self.private_key.public_key()
        return self.public_key

    def get_shared_secret(self, peer_public_key):
        """计算共享密钥"""
        # 这里需要实现ECDH密钥交换
        # 提示：使用自己的私钥和对方的公钥计算共享密钥
        pass

class SimpleAES:
    def __init__(self):
        self.key = None

    def derive_key(self, shared_secret):
        """从共享密钥派生AES密钥"""
        # 使用SHA256从共享密钥派生固定长度的AES密钥
        pass

    def encrypt(self, plaintext):
        """AES加密"""
        pass

    def decrypt(self, ciphertext):
        """AES解密"""
        pass
