__author__ = 'Daniel Sánchez'
import os
import socket, ssl

s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
ssl_sock = ssl.wrap_socket(s,
                           ca_certs="sslserver.cer",
                           certfile="sslclient.crt.pem",
                           keyfile="sslclient.key.pem",
                           cert_reqs=ssl.CERT_REQUIRED,
                           ssl_version=ssl.PROTOCOL_TLSv1)
ssl_sock.connect(('127.0.0.1', 7070))
ssl_sock.send(b'hello ~MySSL !')
data = ssl_sock.recv(4096)
print(data)
print(data.decode("UTF-8"))
ssl_sock.close()