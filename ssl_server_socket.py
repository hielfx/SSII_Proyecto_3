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
                 ssl_version=ssl.PROTOCOL_SSLv23,  #Comunicatio+n protocol
                 ciphers="DEFAULT",
                 bind_and_activate=True):
        TCPServer.__init__(self, server_address, RequestHandlerClass, bind_and_activate)
        self.certfile = certfile
        self.keyfile = keyfile
        self.ssl_version = ssl_version
        self.ciphers=ciphers

    def get_request(self):
        newsocket, fromaddr = self.socket.accept()
        connstream = ssl.wrap_socket(newsocket,
                                 server_side=True,
                                 certfile = self.certfile,
                                 ca_certs="sslserver.cer",  # We trust in all the certificates signed by this ca (or this ca itself)
                                 cert_reqs=ssl.CERT_REQUIRED,
                                 keyfile = self.keyfile,
                                 ssl_version = self.ssl_version,
                                 ciphers=self.ciphers)
        return connstream, fromaddr


class SSLTCPServerSocket(ThreadingMixIn, SSLTCPServerSocket):
    pass


class MyTCPHandler(StreamRequestHandler):
    def handle(self):

        def check_username_and_password(username,password):
            logger.get_logger().info("Checking username and password...")
            return username == "PSI3-SSII" and password == "SSII-PSI3"

        # self.request is the TCP socket connected to the client
        logger.get_logger().info("Retrieving data...")
        self.data = self.request.recv(1024).strip()

        data = self.data.decode("utf-8")  # We decode the bytes into an UTF-8 string
        if data is not None and data != '':
            logger.get_logger().info("{0} wrote: {1}".format(self.client_address[0], data))
            dict = json.loads(data)  # We create a dictionary from the json
            # print(dict)

            message = json.loads(dict['message'])  # The client message (username, password and the message itself)
            message_username = json.loads(message)['username']
            message_password = json.loads(message)['password']
            message_message = json.loads(message)['message']

            nonce = dict['nonce']  # The client nonce
            hmac = dict['hmac']  # The message hmac sent by the client

            replay = crypt_utils.check_nonce_in_db(nonce)
            # We check if the NONCE is already in the db
            if not replay:
                # If the NONCE is not in the db, we check the integrity of the message and store it in the database
                integrity = crypt_utils.check_integrity(hmac, message)
                if integrity:
                # If the integrity is correct, we check the user and password.
                # We do it this way because an attacker could have modified the username or password
                    user_password = check_username_and_password(message_username, message_password)
                    if user_password:
                        logger.get_logger().info("The username and password are correct.")
                        # The integrity and the username-password are correct. We can store the message
                        # Otherwise we don't store the message
                        crypt_utils.insert_hmac(nonce, hmac, message_message)
                    else:
                        logger.get_logger().warn("The username and password are incorrect!.")


                else:
                    # We store the message if the integrity fails
                    # so we can check what information may have been compromised and consider the risks
                    crypt_utils.insert_hmac(nonce, hmac, message_message, 0)  # The integrity fails
                    user_password = "Not checked"
            else:
                integrity = "Not checked"

            dict = {'replay': replay,
                    'integrity': integrity,
                    'user_password': user_password,
                    "message": message_message,
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