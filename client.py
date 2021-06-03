import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import random
import sys
import socket
import string

server_public_key = 'bw4NsfwqNeFGgHBS3YGeAvrJ8ZqZEkk079CHh8VM8-w='
server_private_key = ''
my_public_key = ''
my_private_key = ''


def encrypt(message, key):
    f = Fernet(key)
    return f.encrypt(message.encode())


def decrypt(data=None, key=b'WrongKey'):
    return Fernet(key).decrypt(data)


def get_key():
    password = ''.join([random.choice(string.ascii_letters + string.digits) for i in range(24)])
    password_provided = password  # This is input in the form of a string
    password = password_provided.encode()  # Convert to type bytes
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )

    key = base64.urlsafe_b64encode(kdf.derive(password))

    return key.decode()  # Can only use kdf once


def set_my_public_key(my_key):
    global my_public_key
    my_public_key = my_key


def set_my_private_key(my_key):
    global my_private_key
    my_private_key = my_key


def set_server_private_key(server_key):
    global server_private_key
    server_private_key = decrypt(server_key, my_public_key.encode()).decode()


def bind_connection(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # connect to server on local computer
    sock.connect((host, port))
    return sock


def print_keys_input():
    show_keys_input = input('do you want to see the keys? (y/n): ').lower()
    should_show_keys = (show_keys_input == 'y')

    if should_show_keys:
        start_line = '-------------------------------------------------------------------'
        half = (len(start_line) // 2)
        print(start_line)
        print(f"{(half - 5) * ' '}Client{(half - 3) * ' '}")
        print('client_public_key: ', my_public_key)
        print('client_private_key: ', my_private_key)
        print(f"{(half - 5) * ' '}Server{(half - 3) * ' '}")
        print('server_public_key: ', server_public_key)
        print('server_private_key: ', server_private_key)
        print(start_line)


def send_message(data, connection):
    connection.send(data)


def take_message(connection):
    # message you send to server
    while True:
        message = input("Enter your message ('q' to exit): ")

        # message sent to server
        send_message(encrypt(message, server_private_key.encode()), connection)

        # message received from server
        data = connection.recv(1024)

        # print the received message
        # here it would be a reverse of sent message
        print(decrypt(data, my_private_key.encode()).decode())
        if message.lower() == 'q':
            break
    connection.close()


def main():
    sock = bind_connection('127.0.0.1', 2004)

    set_my_public_key(get_key())

    send_message(encrypt(my_public_key, server_public_key), sock)

    try:
        set_server_private_key(sock.recv(2048))
    except Exception as error:
        print(error, file=sys.stderr)
        return

    set_my_private_key(get_key())

    send_message(encrypt(my_private_key, server_private_key), sock)
    print_keys_input()

    take_message(sock)


if __name__ == '__main__':
    main()
