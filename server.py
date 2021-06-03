import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import random
import socket
import sys
import string

import _thread as thread

thread_count = 0


# users_keys = {}
# server_public_key = 'bw4NsfwqNeFGgHBS3YGeAvrJ8ZqZEkk079CHh8VM8-w='


def bind_connection(host, port):
    """
    The function create the socket and bind it
    :param host: the host ip
    :param port: the port
    :return: the connection
    """
    _server_side_socket = socket.socket()

    try:
        _server_side_socket.bind((host, port))
    except socket.error as error:
        print(error, file=sys.stderr)

    print('The server is listening...')
    _server_side_socket.listen(5)
    return _server_side_socket


public_key = 'bw4NsfwqNeFGgHBS3YGeAvrJ8ZqZEkk079CHh8VM8-w='
users_keys = {}


def encrypt(message, key):
    """
    This function encrypt the message with a given key
    :param message: the message to encrypt
    :param key: the key to encrypt with
    :return: the encrypted message
    """
    f = Fernet(key)
    return f.encrypt(message)  # Encrypt the bytes. The returning object is of type bytes


def decrypt(data=None, key=b'WrongKey'):
    """
    The function decrypt the encrypted message
    :param data: the message to decrypt
    :param key: the key to decrypt with
    :return: the decrypted message
    """
    return Fernet(key).decrypt(data)


def get_key():
    """
    The function generate new key
    :return: the key
    """
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


def get_send_keys(connection, _address):
    """
    The function handle the keys transfer from the server
    :param connection: The connection
    :param _address: the user information
    :return: Nothing important
    """
    client_public_key = decrypt(connection.recv(2048),
                                public_key.encode()).decode()  # the client's public key

    server_privat_key = get_key()  # generate new private key for the server

    user_info = _address[0] + ':' + str(_address[1])

    users_keys[user_info] = [client_public_key, server_privat_key]  # save the keys
    start_line = f'----------------------- {user_info} ----------------------------- '
    print(start_line)
    half = (len(start_line) // 2)
    print(f"{(half - 7) * ' '}Client{(half - 3) * ' '}")
    print('client_public_key: ', client_public_key)

    # send the server private key encrypted by the client's public key
    send_private_key = encrypt(server_privat_key.encode(), client_public_key.encode())

    connection.sendall(send_private_key)

    client_private_key = decrypt(connection.recv(2048), server_privat_key.encode()).decode()

    print('client_private_key: ', client_private_key)
    print(f"{(half - 7) * ' '}Server{(half - 3) * ' '}")
    print('server_public_key: ', public_key)
    print('server_privat_key: ', server_privat_key)
    print((len(start_line) - 1) * '-')

    users_keys[user_info].append(client_private_key)
    return len(start_line)


def change_thread_number():
    """
    The function update the online members
    :return: None
    """
    global thread_count
    thread_count -= 1


def multi_threaded_client(connection, _address):
    """
    The function handle all the multi client threads
    :param connection: the connection
    :param _address: the user information
    :return: None
    """
    start_len = ''
    try:
        start_len = get_send_keys(connection, _address)
        user_info = _address[0] + ':' + str(_address[1])

        while True:
            data = decrypt(connection.recv(2048), users_keys[user_info][1]).decode()
            print((start_len - 1) * '-')
            print('Data from ', user_info, '  ->  ', data)
            print((start_len - 1) * '-')
            if not data:
                break
            if data.lower() == 'users':
                msg = 'Users Online: ' + str(thread_count)
                connection.sendall(encrypt(msg.encode(), users_keys[user_info][2].encode()))
            elif data == 'q':
                connection.sendall(encrypt('Server message: Bye Bye'.encode(), users_keys[user_info][2].encode()))
                raise socket.error
            else:
                response = 'Server message: ' + data
                connection.sendall(encrypt(response.encode(), users_keys[user_info][2].encode()))
    except socket.error:
        print((start_len - 1) * '-')
        print('Remove client: ' + _address[0] + ':' + str(_address[1]))
        print((start_len - 1) * '-')
        change_thread_number()
        connection.close()


def main():
    global thread_count
    server_side_socket = bind_connection('127.0.0.1', 2004)
    while True:
        Client, address = server_side_socket.accept()
        thread.start_new_thread(multi_threaded_client, (Client, address,))
        thread_count += 1


if __name__ == '__main__':
    main()
