from http import client
import socket

server = socket.socket()

server_ip = "IP"
port = 9999

server.bind((server_ip, port))
server.listen(1)
print("server ready")

client, addr = server.accept()
print("connected")

recv_msg = client.recv(1024)
msg = str(recv_msg, 'utf-8')
print(msg)

client.sendall(recv_msg)
print("message send")

client.close()
server.close()