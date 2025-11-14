import socket

def tls_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 12345))
    print("连接成功!")
    try:
        client_socket.send("Hello Server!".encode('utf-8'))
        print("握手消息已发送")
    except :
        print("连接失败")
    finally:
        client_socket.close()
#接受客服端信息，接受发送公钥
if __name__ == "__main__":
    tls_client()
