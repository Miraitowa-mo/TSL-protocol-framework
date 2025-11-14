import socket

def tls_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 12345))
    server_socket.listen(1)
    print("TLS服务器启动，等待客户端连接ing")

    while True:
        try:
            client_socket, client_address = server_socket.accept()
            print(f"接收到来自 {client_address} 的连接")
            # 接收客户端消息
            while True:
                data = client_socket.recv(1024)
                if not data: 
                    print("客户端断开连接")
                    break
                message = data.decode()
                print(f"收到消息: {message}")
        except Exception as e:
            print(f"错误: {e}")
         
if __name__ == "__main__":
    tls_server()
