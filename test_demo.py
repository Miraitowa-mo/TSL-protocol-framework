# test_demo.py - 测试RSA功能
from src.common.crypto_utils import SimpleRSA, export_public_key, import_public_key

def main():
    print("=== 测试RSA签名和加密功能 ===")

    # 创建两个用户模拟A和B
    alice = SimpleRSA()
    bob = SimpleRSA()

    # 1. 生成密钥对
    print("1. 生成RSA密钥对...")
    alice.generate_keys()
    bob.generate_keys()
    print("   ✅ 密钥对生成成功")

    # 2. 测试签名验证
    print("\n2. 测试数字签名...")
    message = "Hello, this is a secret message!"
    print(f"   原始消息: {message}")

    # Alice对消息签名
    signature = alice.sign_message(message)
    print(f"   Alice的签名: {signature[:50]}...")

    # Bob验证Alice的签名
    alice_public_key_str = export_public_key(alice.public_key)
    alice_public_key = import_public_key(alice_public_key_str)

    is_valid = bob.verify_signature(alice_public_key, message, signature)
    print(f"   签名验证结果: {'✅ 成功' if is_valid else '❌ 失败'}")

    # 3. 测试加密解密
    print("\n3. 测试加密解密...")
    secret_message = "Confidential data 123"
    print(f"   原始消息: {secret_message}")

    # Bob用Alice的公钥加密
    encrypted = bob.encrypt_message(alice_public_key, secret_message)
    print(f"   加密后的消息: {encrypted[:50]}...")

    # Alice用自己的私钥解密
    decrypted = alice.decrypt_message(encrypted)
    print(f"   解密后的消息: {decrypted}")
    print(f"   解密验证: {'✅ 成功' if decrypted == secret_message else '❌ 失败'}")

    print("\n=== 所有测试完成 ===")


if __name__ == "__main__":
    main()