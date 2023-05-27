import rsa

class Enc:
    def __init__(self, pub_key, priv_key):
        self.pub_key = pub_key
        self.priv_key = priv_key

    def send_public_key(self, sock):
        str_pub_key = str(self.pub_key)[10:-1]
        sock.send(str('KEY|' + str_pub_key).encode('utf-8'))
        print('Public key sent successfully!')

    def send_aes_key(self, sock, aes):
        sock.send(aes)
        print('AES key sent successfully!')

    def encrypt_message(self, message, peer_public_key):
        crypto = rsa.encrypt(message, peer_public_key)
        return crypto

    def decrypt_message(self, crypto):
        message = rsa.decrypt(crypto, self.priv_key)
        return message