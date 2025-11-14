import socket
from src.common.protocol import *
from src.common.crypto_utils import SimpleRSA, export_public_key, import_public_key


class SecureClient:
    def __init__(self, host='localhost', port=12345):
        self.host = host
        self.port = port
        self.rsa = SimpleRSA()

    def connect(self):
        """连接服务器并完成安全握手"""
        self.rsa.generate_keys()
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((self.host, self.port))
        print(f"连接到安全服务器 {self.host}:{self.port}")

        try:
            # 1. 发送Hello
            hello_msg = HelloMessage()
            client_socket.send(hello_msg.to_json().encode())

            # 2. 接收Hello
            data = client_socket.recv(1024).decode()
            server_msg = ProtocolMessage.from_json(data)

            # 3. 发送公钥
            pubkey_msg = PublicKeyMessage(
                export_public_key(self.rsa.public_key),
                "client_ecc_key"
            )
            client_socket.send(pubkey_msg.to_json().encode())

            # 4. 接收服务器公钥
            data = client_socket.recv(1024).decode()
            server_pubkey_msg = ProtocolMessage.from_json(data)
            server_rsa_pubkey = import_public_key(server_pubkey_msg.data["rsa_public_key"])

            # 5. 接收签名挑战并响应
            data = client_socket.recv(1024).decode()
            challenge_msg = ProtocolMessage.from_json(data)
            challenge = challenge_msg.data["challenge"]

            # 对挑战进行签名
            signature = self.rsa.sign_message(challenge)
            signature_msg = SignatureResponseMessage(signature, challenge)
            client_socket.send(signature_msg.to_json().encode())

            # 6. 接收最终结果
            data = client_socket.recv(1024).decode()
            result_msg = ProtocolMessage.from_json(data)

            if result_msg.type == MessageType.ENCRYPTED_DATA:
                print(f"服务器消息: {result_msg.data['encrypted_data']}")
                print("安全握手成功!")
            else:
                print("握手失败")

        except Exception as e:
            print(f"错误: {e}")
        finally:
            client_socket.close()


if __name__ == "__main__":
    client = SecureClient()
    client.connect()