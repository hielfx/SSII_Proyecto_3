__author__ = 'Daniel Sánchez'
# encoding:utf-8

import socketserver
import sys
import traceback
import logger  # Custom logger module
import crypt_utils  # Custom utils module
import json
import socket as sck
import ssl
from ssl_server_socket import SSLTCPServerSocket, MyTCPHandler
# import gui_utils as g_utl


class SSLServerSocket():
    """This is the Server Socket class.
    It will provide methods to run and close the Server Socket."""

    def __init__(self,
                 host,
                 port,  # Server address (host,port)
                 certfile,  # Certificate path
                 keyfile,  # Key path
                 ssl_version=ssl.PROTOCOL_TLSv1,  #Comunication protocol
                 bind_and_activate=True):

        # class MyTCPHandler(socketserver.BaseRequestHandler):
        #     """Request handler for our server"""
        #
        #     def handle(self):
        #         # self.request is the TCP socket connected to the client
        #         logger.get_logger().info("Retrieving data...")
        #         self.data = self.request.recv(1024).strip()
        #
        #         data = self.data.decode("utf-8")  # We decode the bytes into an UTF-8 string
        #         if data is not None and data != '':
        #             logger.get_logger().info("{0} wrote: {1}".format(self.client_address[0], data))
        #             dict = json.loads(data)  # We create a dictionary from the json
        #             # print(dict)
        #
        #             message = dict['message']  # The client message
        #             nonce = dict['nonce']  # The client nonce
        #             hmac = dict['hmac']  # The message hmac sent by the client
        #
        #             replay = crypt_utils.check_nonce_in_db(nonce)
        #             # We check if the NONCE is already in the db
        #             if not replay:
        #                 # If the NONCE is not in the db, we check the integrity of the message and store it in the database
        #                 integrity = crypt_utils.check_integrity(hmac, message)
        #                 if integrity:
        #                     crypt_utils.insert_hmac(nonce, hmac)  # The integrity is correct
        #                 else:
        #                     crypt_utils.insert_hmac(nonce, hmac, 0)  # The integrity fails
        #             else:
        #                 integrity = "Not checked"
        #
        #             dict = {'replay': replay,
        #                     'integrity': integrity,
        #                     # "edited": edited,
        #                     "message": message,
        #                     "hmac": hmac,
        #                     "nonce": nonce}
        #
        #             _data = json.dumps(dict)
        #
        #             logger.get_logger().info("Sending data back to {0} (client socket).".format(self.client_address[0]))
        #             # just send back the same data, but upper-cased
        #             self.request.sendall(bytes(str.encode(_data)))
        #             logger.get_logger().info("Data sent.")
        #         else:
        #             logger.get_logger().info("No data was sent.")

        try:
            logger.get_logger().info("Creating the server socket...")
            # socketserver.TCPServer.__init__(self, (host, port), MyTCPHandler, bind_and_activate)
            self.certfile = certfile
            self.keyfile = keyfile
            self.ssl_version = ssl_version

            #TODO: CHECK THIS METHOD AND THE CLIENT
            s = SSLTCPServerSocket((host, port), MyTCPHandler, certfile, keyfile)
            self.socket = s
            self.host = host
            self.port = port
            # s.bind(host, port)

        except Exception:
            traceback.print_exc()
            logger.generate_error_message("Error while trying to create the socket with ip '{0}:{1}'".format(sck.gethostbyname(sck.gethostname()), port))

    def run_server(self):
        logger.get_logger().info("Starting server...")
        try:
            logger.get_logger().info("Server socket started successfully. The server will run forever\n")
            self.socket.serve_forever()  # The server will run forever
            # self.socket.listen(5)

        except Exception:
            logger.generate_error_message("Error while trying to start the server.")

    def handle_request(self):
        logger.get_logger().info("Starting server...")
        try:
            logger.get_logger().info("Server started successfully. The server will handle 1 request\n")
            self.socket.handle_request()
        except Exception:
            logger.generate_error_message("Error while trying to start the server.")

    def stop_server(self):
        logger.get_logger().info("Stopping the server...")
        try:
            self.socket.shutdown(sck.SHUT_RDWR)  # To close the server
            # self.socket.server_close()
            logger.get_logger().info("Server stopped successfully.\n")

        except Exception:
            logger.generate_error_message("Error while trying to stop the server.")

    def close_server(self):
        logger.get_logger().info("Closing the server...")
        try:
            self.socket.server_close()  # To close the server
            # self.socket.server_close()
            logger.get_logger().info("Server closed successfully.\n\n")

        except Exception:
            logger.generate_error_message("Error while trying to close the server.")


if __name__ == "__main__":
    # g_utl.generate_server_interface()
    pass
    # server = ServerSocket()
    # server.run_server()