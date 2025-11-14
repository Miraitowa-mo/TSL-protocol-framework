import json
import base64
from enum import Enum


class MessageType(Enum):
    """消息类型枚举"""
    HELLO = "hello"  # 初始问候
    PUBLIC_KEY_EXCHANGE = "public_key"  # 公钥交换
    SIGNATURE_CHALLENGE = "challenge"  # 签名挑战
    SIGNATURE_RESPONSE = "signature"  # 签名响应
    ENCRYPTED_DATA = "encrypted_data"  # 加密数据
    ERROR = "error"  # 错误消息


class ProtocolMessage:
    """协议消息基类"""

    def __init__(self, msg_type: MessageType, data: dict = None):
        self.type = msg_type
        self.data = data or {}

    def to_json(self) -> str:
        """将消息转换为JSON字符串"""
        message_dict = {
            "type": self.type.value,
            "data": self.data
        }
        return json.dumps(message_dict)

    @classmethod
    def from_json(cls, json_str: str):
        """从JSON字符串创建消息对象"""
        try:
            data = json.loads(json_str)
            msg_type = MessageType(data["type"])
            return cls(msg_type, data.get("data", {}))
        except (KeyError, ValueError, json.JSONDecodeError) as e:
            raise ValueError(f"无效的消息格式: {e}")


# 具体的消息类型类
class HelloMessage(ProtocolMessage):
    """初始问候消息"""

    def __init__(self, version="1.0", supported_algorithms=None):
        if supported_algorithms is None:
            supported_algorithms = ["RSA", "ECDH", "AES-GCM"]

        data = {
            "version": version,
            "algorithms": supported_algorithms
        }
        super().__init__(MessageType.HELLO, data)


class PublicKeyMessage(ProtocolMessage):
    """公钥交换消息"""

    def __init__(self, rsa_public_key: str, ecc_public_key: str = None):
        data = {
            "rsa_public_key": rsa_public_key,
            "ecc_public_key": ecc_public_key
        }
        super().__init__(MessageType.PUBLIC_KEY_EXCHANGE, data)


class SignatureChallengeMessage(ProtocolMessage):
    """签名挑战消息"""

    def __init__(self, challenge_data: str):
        data = {
            "challenge": challenge_data
        }
        super().__init__(MessageType.SIGNATURE_CHALLENGE, data)


class SignatureResponseMessage(ProtocolMessage):
    """签名响应消息"""

    def __init__(self, signature: str, challenge_data: str):
        data = {
            "signature": signature,
            "challenge": challenge_data
        }
        super().__init__(MessageType.SIGNATURE_RESPONSE, data)


class EncryptedDataMessage(ProtocolMessage):
    """加密数据消息"""

    def __init__(self, encrypted_data: str, message_id: str = None):
        data = {
            "encrypted_data": encrypted_data,
            "message_id": message_id or base64.b64encode(b"default").decode('utf-8')
        }
        super().__init__(MessageType.ENCRYPTED_DATA, data)


class ErrorMessage(ProtocolMessage):
    """错误消息"""

    def __init__(self, error_code: str, error_message: str):
        data = {
            "error_code": error_code,
            "error_message": error_message
        }
        super().__init__(MessageType.ERROR, data)


# 协议握手流程管理
class HandshakeProtocol:
    """握手协议管理器"""

    def __init__(self):
        self.steps = [
            "hello_exchange",
            "key_exchange",
            "authentication",
            "ready"
        ]
        self.current_step = 0

    def get_next_step(self):
        """获取下一步握手步骤"""
        if self.current_step < len(self.steps):
            return self.steps[self.current_step]
        return None

    def advance_step(self):
        """前进到下一步"""
        if self.current_step < len(self.steps) - 1:
            self.current_step += 1
            return True
        return False

    def is_handshake_complete(self):
        """检查握手是否完成"""
        return self.current_step >= len(self.steps) - 1


# 工具函数
def create_challenge_data() -> str:
    """创建随机挑战数据"""
    import os
    challenge = os.urandom(32)  # 256位随机数据
    return base64.b64encode(challenge).decode('utf-8')


def validate_challenge_response(original_challenge: str, response_challenge: str) -> bool:
    """验证挑战响应是否匹配"""
    return original_challenge == response_challenge