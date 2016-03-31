__author__ = 'Daniel Sánchez'
# encoding:utf-8
import tkinter.messagebox as msgbox
import tkinter as tk
import logger
import binascii
import os
from hashlib import sha1, sha224, sha256, sha384, sha512, md5
import hmac
import sqlite3
import datetime
import socket
import hashlib
import json

app_name = "socket_app_py"

global total_scanned_messages, stable_integrity_messages
total_scanned_messages = 0
stable_integrity_messages = 0


def generate_nonce():
    u_id = socket.gethostname()
    a_id = "banktransfer"
    timeStamp = str(datetime.datetime.now())
    salt = "SSII1516"

    result = u_id+a_id+timeStamp+salt

    return hashlib.sha256(str.encode(result)).hexdigest()


def check_nonce_in_db(nonce):
    check_table()
    logger.get_logger().info("Checking the NONCE...")
    table_name = "transmission"
    conn = sqlite3.connect(str(app_name)+".db")
    statement = "SELECT COUNT(*) FROM {0} where nonce like ?;".format(table_name)
    result = True
    try:
        cursor = conn.execute(statement, (nonce,))
        count = cursor.fetchone()[0]
        if count is not None and count == 0:
            logger.get_logger().info("The NONCE {0} isn't in the database".format(nonce))
            result = False
        else:
            logger.get_logger().warn("\n    -> The NONCE {0} is already in the database!".format(nonce))

    except:
        logger.generate_error_message("Error while trying to check the NONCE.")

    return result

def hash_message(message, key=os.urandom(8), mode=sha256):
        """This method hash the message with a given key and hash algorithm and returns a tuple with the hashed message and the key.
        The default hash mode is sha256."""

        # logger.get_logger().info("Obtaining key...")
        # Generate a random key with 8 bytes (64 bits)
        # logger.get_logger().debug("Retrieved the key: " + str(key))

        # hexified_key = binascii.hexlify(key)
        # logger.get_logger().debug("Hexified key: " + str(hexified_key))

        hexified_hmac = ""

        exception = False
        try:

            # logger.get_logger().info("Hashing the message...")
            hashed = hmac.new(key, message, mode)

            hexified_hmac = hashed.hexdigest()
            # logger.get_logger().info("Generated HMAC: " + str(hexified_hmac))


        except Exception:
            logger.generate_error_message("Error while hashing the message")
            exception = True

        if not exception:
            return tuple([key, hexified_hmac])
        else:
            return None


def check_table():
    conn = sqlite3.connect(str(app_name)+".db")
    cursor = None
    table_name = "transmission"
    try:
        # We check if the table exist. If the table doesn't exist we create it.
        check_table = "SELECT * FROM sqlite_master WHERE name ='{0}' and type='table';".format(table_name)
        logger.get_logger().debug("Check table statement: " + check_table)

        cursor = conn.execute(check_table)
        logger.get_logger().info("Checking if the table {0} exists...".format(table_name))

        # If cursor.fetch() is None means that the table desn't exist, so we have to create it.
        if cursor.fetchone() is None:
            # We create the create_table script
            logger.get_logger().info("The table {0} doesn't exists. Creating table...".format(table_name))

            create_table = "CREATE TABLE {0} (id INTEGER PRIMARY KEY AUTOINCREMENT, nonce TEXT UNIQUE, insert_date DATE, hex_hmac TEXT, message TEXT, integrity NUMERIC);".format(
                table_name)
            conn.execute(create_table)

            conn.commit()  # We commit the changes
            logger.get_logger().info("Table '{0}' created correctly\n".format(table_name))

        else:
            logger.get_logger().info("The table {0} already exists\n".format(table_name))

    except Exception:
        logger.generate_error_message("Error while connecting to the database.")

    cursor.close()
    return cursor


def insert_hmac(nonce, hmac, message, integrity=1):
    table_name = "transmission"
    conn=sqlite3.connect(str(app_name)+".db")
    logger.get_logger().info("Inserting NONCE in the Data Base...")
    insert = "INSERT INTO {0} (nonce, insert_date, hex_hmac, integrity, message) VALUES ('{1}',?,'{2}',?,'{3}');".format(table_name, nonce, hmac, message)
    # print(insert)
    logger.get_logger().debug("INSERT statement: " + insert)
    # print(insert,(_key,))
    cursor = None
    try:
        now = datetime.datetime.now()
        now.strftime('%Y-%m-%d %H:%M:%S')
        cursor = conn.execute(insert, (now, integrity,))
        conn.commit()
        logger.get_logger().info("The NONCE has been saved correctly in the Data Base\n")

    except Exception:
        logger.generate_error_message("Error while trying to insert the NONCE in the Data Base\n")

    return cursor


def check_integrity(hmac, message):
    key = "P$1_m3$$4G3_k3Y"
    logger.get_logger().info("Checking the integrity of the message '{0}'".format(message))
    # message_hmac = hash_message(message=message, key=bytes(str.encode(key)))[1]
    message_hmac = hash_message(str.encode(json.dumps(message)), key=bytes(str.encode(key)), mode=sha256)[1]
    if hmac == message_hmac:
        logger.get_logger().info("The integrity of the message '{0}' is correct".format(message))
        globals()['stable_integrity_messages'] += 1
        return True
    else:
        logger.get_logger().warn("\n     --> The integrity of the message '{0}' failed!\n".format(message))
        return False


if __name__ == "__main__":
    pass