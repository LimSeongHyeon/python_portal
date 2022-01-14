from http import client
import socket
from cryptography.fernet import Fernet
import time

server = socket.socket()

server_ip = [SERVER_ADDRESS]
port = [SERVER_PORT]
key = [ENCRYPTO_KEY]
fernet = Fernet(key)

server.bind((server_ip, port))
server.listen(1)
print("server ready")

while True:
    client, addr = server.accept()
    print("connected")
    print(client)
    print(addr)

    recv_msg = client.recv(1024)
    msg = str(fernet.decrypt(recv_msg), 'utf-8')
    print(msg)

    time.sleep(5) # Something Activate

    client.sendall("Success".encode('utf-8'))
    print("Success message send")

    client.close()
server.close()