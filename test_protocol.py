# test_protocol.py
from src.common.protocol import *


def test_protocol_messages():
    # 测试消息创建和序列化
    hello_msg = HelloMessage()
    json_str = hello_msg.to_json()
    print(f"Hello消息: {json_str}")

    # 测试消息解析
    parsed_msg = ProtocolMessage.from_json(json_str)
    print(f"解析后的类型: {parsed_msg.type}")

    # 测试公钥消息
    pubkey_msg = PublicKeyMessage("fake_rsa_key", "fake_ecc_key")
    print(f"公钥消息: {pubkey_msg.to_json()}")


if __name__ == "__main__":
    test_protocol_messages()