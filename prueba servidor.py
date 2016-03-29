__author__ = 'Daniel Sánchez'
from socketserver import TCPServer, ThreadingMixIn, StreamRequestHandler
import ssl


class SSLTCPServer(TCPServer):
    def __init__(self,
                 server_address,  # Server address (host,port)
                 RequestHandlerClass,
                 certfile,  # Certificate path
                 keyfile,  # Key path
                 ssl_version=ssl.PROTOCOL_TLSv1,  #Comunication protocol
                 bind_and_activate=True):
        TCPServer.__init__(self, server_address, RequestHandlerClass, bind_and_activate)
        self.certfile = certfile
        self.keyfile = keyfile
        self.ssl_version = ssl_version

    def get_request(self):
        newsocket, fromaddr = self.socket.accept()
        connstream = ssl.wrap_socket(newsocket,
                                 server_side=True,
                                 certfile = self.certfile,
                                 ca_certs="sslserver.cer",  # We trust in all the certificates signed by this ca (or this ca itself)
                                 cert_reqs=ssl.CERT_REQUIRED,
                                 keyfile = self.keyfile,
                                 ssl_version = self.ssl_version)
        return connstream, fromaddr


class SSLTCPServer(ThreadingMixIn, SSLTCPServer):
    pass


class MyTCPHandler(StreamRequestHandler):
    def handle(self):
        data = self.connection.recv(4096)
        # self.wfile.write(data)
        _data = data.decode("utf-8")
        print(_data)
        self.request.sendall(bytes(str.encode(_data.upper())))
#test code
SSLTCPServer(('127.0.0.1', 7070), MyTCPHandler, "sslserver.crt.pem","sslserver.key.pem").serve_forever()