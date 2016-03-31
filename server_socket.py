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
                 ssl_version=ssl.PROTOCOL_SSLv23,  #Comunication protocol
                 bind_and_activate=True):

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
            self.socket.shutdown()  # To close the server
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