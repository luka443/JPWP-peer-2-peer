from encryption import Enc
import os
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad
class Rcv:
    def __init__(self, pub_key, priv_key):
        self.pub_key = pub_key
        self.priv_key = priv_key
        self.peer_key = None
        self.aes_key = None

    def receive_public_key(self, key):
        key = key.split('|')[-1]
        self.peer_key = key
        print('Key received successfully!')

    def receive_aes_key(self, key):
        enc = Enc(self.pub_key, self.priv_key)
        key = enc.decrypt_message(key)
        self.aes_key = key
        print('AES key received successfully!')

    def receive_file(self, sock, file_info):
        file, file_name, file_size = file_info.split('|')
        file_size = int(file_size)
        print('Receiving file:', file_name)
        file_name = "recived" + file_name
        cipher = AES.new(self.aes_key, AES.MODE_ECB)

        with open(file_name, 'wb') as file:
            bytes_received = 0
            while bytes_received < file_size:
                data = sock.recv(1024)
                data = unpad(cipher.decrypt(data),16)
                file.write(data)
                bytes_received += len(data)
                #print('Progress:', (bytes_received / file_size) * 100, '%')

        print('File received successfully!')

    def send_file(self, sock, message):
        _, file_path = message.split(' ')
        file_name = file_path.split('/')[-1]
        file_size = os.path.getsize(file_path)
        cipher = AES.new(self.aes_key, AES.MODE_ECB)
        data = ('FILE|' + file_name + '|' + str(file_size)).encode('utf-8')
        data = cipher.encrypt(pad(data, 16))
        sock.send(data)

        with open(file_path, 'rb') as file:
            while True:
                data = file.read(1024)
                if not data:
                    break

                data2 = cipher.encrypt(pad(data, 16))
                sock.send(data2)

        print('File sent successfully!')
    def receive_messages(self, sock):
        cipher = AES.new(self.aes_key, AES.MODE_ECB)

        while True:
            try:
                data = sock.recv(1024)
                data = unpad(cipher.decrypt(data), 16)
                data= data.decode()

                if data.startswith('FILE'):
                    self.receive_file(sock, data)
                else:
                    print('Received:', data)

            except ConnectionResetError:
                print('Peer disconnected')
                break