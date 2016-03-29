__author__ = 'Daniel Sánchez'
from socketserver import TCPServer, ThreadingMixIn, StreamRequestHandler
import logger  # Custom logger module
import crypt_utils  # Custom utils module
import json
import ssl


class SSLTCPServerSocket(TCPServer):
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


class SSLTCPServerSocket(ThreadingMixIn, SSLTCPServerSocket):
    pass


class MyTCPHandler(StreamRequestHandler):
    def handle(self):
        # self.request is the TCP socket connected to the client
        logger.get_logger().info("Retrieving data...")
        self.data = self.request.recv(1024).strip()

        data = self.data.decode("utf-8")  # We decode the bytes into an UTF-8 string
        if data is not None and data != '':
            logger.get_logger().info("{0} wrote: {1}".format(self.client_address[0], data))
            dict = json.loads(data)  # We create a dictionary from the json
            # print(dict)

            message = dict['message']  # The client message
            nonce = dict['nonce']  # The client nonce
            hmac = dict['hmac']  # The message hmac sent by the client

            replay = crypt_utils.check_nonce_in_db(nonce)
            # We check if the NONCE is already in the db
            if not replay:
                # If the NONCE is not in the db, we check the integrity of the message and store it in the database
                integrity = crypt_utils.check_integrity(hmac, message)
                if integrity:
                    crypt_utils.insert_hmac(nonce, hmac)  # The integrity is correct
                else:
                    crypt_utils.insert_hmac(nonce, hmac, 0)  # The integrity fails
            else:
                integrity = "Not checked"

            dict = {'replay': replay,
                    'integrity': integrity,
                    # "edited": edited,
                    "message": message,
                    "hmac": hmac,
                    "nonce": nonce}

            _data = json.dumps(dict)

            logger.get_logger().info("Sending data back to {0} (client socket).".format(self.client_address[0]))
            # just send back the same data, but upper-cased
            self.request.sendall(bytes(str.encode(_data)))
            logger.get_logger().info("Data sent.")
        else:
            logger.get_logger().info("No data was sent.")

if __name__ == "__main__":
    #test code
    SSLTCPServerSocket(('127.0.0.1', 7070), MyTCPHandler, "sslserver.crt.pem","sslserver.key.pem").serve_forever()