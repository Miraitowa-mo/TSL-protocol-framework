import socket
from src.common.protocol import *
from src.common.crypto_utils import SimpleRSA, export_public_key, import_public_key


class SecureServer:
    def __init__(self, host='localhost', port=12345):
        self.host = host
        self.port = port
        self.rsa = SimpleRSA()

    def start(self):
        """启动安全服务器"""
        self.rsa.generate_keys()
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.host, self.port))
        server_socket.listen(1)
        print(f"安全服务器启动在 {self.host}:{self.port}")

        client_socket, address = server_socket.accept()
        print(f"客户端连接: {address}")

        try:
            # 1. 交换Hello
            data = client_socket.recv(1024).decode()
            client_msg = ProtocolMessage.from_json(data)
            print(f"收到: {client_msg.type}")

            hello_msg = HelloMessage()
            client_socket.send(hello_msg.to_json().encode())

            # 2. 交换公钥
            data = client_socket.recv(1024).decode()
            client_pubkey_msg = ProtocolMessage.from_json(data)
            client_rsa_pubkey = import_public_key(client_pubkey_msg.data["rsa_public_key"])

            # 发送服务器公钥
            server_pubkey_msg = PublicKeyMessage(
                export_public_key(self.rsa.public_key),
                "server_ecc_key"
            )
            client_socket.send(server_pubkey_msg.to_json().encode())

            # 3. 发送签名挑战
            challenge = create_challenge_data()
            challenge_msg = SignatureChallengeMessage(challenge)
            client_socket.send(challenge_msg.to_json().encode())

            # 4. 验证签名响应
            data = client_socket.recv(1024).decode()
            signature_msg = ProtocolMessage.from_json(data)
            client_signature = signature_msg.data["signature"]

            # 验证签名
            is_valid = self.rsa.verify_signature(client_rsa_pubkey, challenge, client_signature)
            print(f"客户端签名验证: {'成功' if is_valid else '失败'}")

            if is_valid:
                success_msg = EncryptedDataMessage("握手成功!可以开始安全通信了")
                client_socket.send(success_msg.to_json().encode())
                print("安全握手完成!")
            else:
                error_msg = ErrorMessage("AUTH_FAILED", "身份验证失败")
                client_socket.send(error_msg.to_json().encode())

        except Exception as e:
            print(f"错误: {e}")
        finally:
            client_socket.close()
            server_socket.close()


if __name__ == "__main__":
    server = SecureServer()
    server.start()