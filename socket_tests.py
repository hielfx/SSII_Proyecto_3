__author__ = 'Daniel Sánchez'
# encoding:utf-8

import unittest  # To test the data
from server_socket import SSLServerSocket
from client_socket import SSLClientSocket
import threading
import time
import crypt_utils as c_utl
import json
import socket
from hashlib import sha256


def send_data_attack(_socket, message, attack=""):
    """This method will simulate replay attacks and integrity attacks.
    If attack='replay', it will send the data twice.
    If attack='integrity', it will change the message after the mac is generated."""

    key = "P$1_m3$$4G3_k3Y"
    hmac = c_utl.hash_message(str.encode(message), key=bytes(str.encode(key)), mode=sha256)[1] # We get the hashed message
    nonce = c_utl.generate_nonce()

    if attack == "integrity":
        # We modified the message to perform an "integrity attack"
        message = "(MODIFIED) -> "+str(message)

    dict = {"message": message,
            "nonce": nonce,
            "hmac": hmac}

    _data = json.dumps(dict)

    try:
        _socket.get_socket().sendall(bytes(str.encode(_data)))

        received = str(_socket.get_socket().recv(1024), "utf-8")

        if attack == "replay":
            # We send the same data to the server to perform a "replay attack"
            _socket.close_socket()
            _socket = SSLClientSocket()
            _socket.connect(port=7171)
            _socket.get_socket().sendall(bytes(str.encode(_data)))
            received = str(_socket.get_socket().recv(1024), "utf-8")
            _socket.close_socket()

        dict = json.loads(received)


        return tuple([dict, nonce])

    except socket.timeout:
        print("Timeout exception")


# Test class:
class ReplayAndIntegrityAttacks(unittest.TestCase):

    # Test cases -------------------------------------------------------------------------------
    def test_replay_attack1(self):
         # With this we start the server for every test
        self.server = SSLServerSocket(port=7171)  # We put the 7171 to evade 7070 sockets executions
        thr = threading.Thread(target=self.server.run_server, args=(), kwargs={})
        thr.start()
        self.client = SSLClientSocket()
        self.client.connect(port=7171)  # We put the 7171 to evade 7070 sockets executions
        sent_message = "origin,destiny,amount"

        dict, sent_nonce = send_data_attack(_socket=self.client, message=sent_message, attack="replay")

        # We get all the data
        message = dict['message']  # The client message returned by the server
        nonce = dict['nonce']  # The client nonce returned by the server
        hmac = dict['hmac']  # The message hmac returned by the server
        replay = dict['replay']  # Sends if it's been a reply attack
        integrity = dict['integrity']  # Sends if the integrity is correct

        self.assertIsNotNone(replay)
        self.assertIsNotNone(integrity)
        self.assertIsNotNone(message)
        self.assertIsNotNone(hmac)
        self.assertIsNotNone(nonce)

        self.assertTrue(replay)
        self.assertEqual(integrity, "Not checked")
        self.assertEqual(nonce, sent_nonce)
        self.assertEqual(sent_message, message)

        self.client.close_socket()
        self.server.stop_server()

        self.client.close_socket()
        self.server.close_server()

    def test_integrity_attack1(self):
         # With this we start the server for every test
        self.server = SSLServerSocket(port=7171)  # We put the 7171 to evade 7070 sockets executions
        thr = threading.Thread(target=self.server.run_server, args=(), kwargs={})
        thr.start()
        self.client = SSLClientSocket()
        self.client.connect(port=7171)  # We put the 7171 to evade 7070 sockets executions
        sent_message = "origin,destiny,amount"

        dict, sent_nonce = send_data_attack(_socket=self.client, message=sent_message, attack="integrity")

        # We get all the data
        message = dict['message']  # The client message returned by the server
        nonce = dict['nonce']  # The client nonce returned by the server
        hmac = dict['hmac']  # The message hmac returned by the server
        replay = dict['replay']  # Sends if it's been a reply attack
        integrity = dict['integrity']  # Sends if the integrity is correct

        self.assertIsNotNone(replay)
        self.assertIsNotNone(integrity)
        self.assertIsNotNone(message)
        self.assertIsNotNone(hmac)
        self.assertIsNotNone(nonce)

        self.assertFalse(replay)
        self.assertFalse(integrity)
        self.assertEqual(nonce, sent_nonce)
        self.assertNotEqual(sent_message, message)
        self.assertEqual(message, "(MODIFIED) -> "+sent_message)

        self.client.close_socket()
        self.server.stop_server()

        self.client.close_socket()
        self.server.close_server()

#TODO GENERATE MORE TESTS
if __name__ == "__main__":
    unittest.main(verbosity=2)  # This will run all the tests. The verbosity=2 param, makes the test display more info.