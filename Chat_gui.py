import socket
import threading
from encryption import Enc
from receiving import Rcv
import rsa
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad
import tkinter as tk
from functools import partial


CbuttonClicked  = False # Bfore first click
JbuttonClicked  = False # Bfore first click


def creatingroomButton():
    global CbuttonClicked
    CbuttonClicked = not CbuttonClicked
    close_window()


def joiningroomButton():
    global JbuttonClicked
    JbuttonClicked = not JbuttonClicked
    close_window()


def close_window():
    window.destroy()


def start_chat():
    global window
    window=tk.Tk()
    window.title("Chat")
    window.geometry("600x400")
    window.configure(background='#b8b088')
    create_room_button = tk.Button(window,bg='#db71e3', height='5', width='20', text="Stwórz pokój", command=creatingroomButton, )
    create_room_button.pack(pady=40)

    join_room_button = tk.Button(window,bg='#7daff0', height='5', width='20',text="Dołącz do pokoju", command=joiningroomButton)
    join_room_button.pack(pady=20)
    window.mainloop()
    (pub_key, priv_key) = rsa.newkeys(512)
    enc = Enc(pub_key, priv_key)
    rcv = Rcv(pub_key, priv_key)

    if CbuttonClicked:
        listen_ip = '0.0.0.0'
        listen_port = 666  # int(input('Enter listening port: '))

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((listen_ip, listen_port))
        sock.listen(1)
        print('Waiting for incoming connection...')

        sending_sock, client_addr = sock.accept()
        print('Connected to peer:', client_addr)

        aes_key = get_random_bytes(16)
        rcv.aes_key = aes_key
        while True:
            data = sending_sock.recv(1024).decode('utf-8')
            if data.startswith('KEY'):
                rcv.receive_public_key(data)
                break

        n, e = str(rcv.peer_key).split(",")
        encrypted_key = enc.encrypt_message(aes_key, rsa.PublicKey(int(n), int(e)))
        enc.send_aes_key(sending_sock, encrypted_key)

        receive_thread = threading.Thread(target=rcv.receive_messages, args=(sending_sock,))
        receive_thread.start()


    elif JbuttonClicked:
        target_ip = '192.168.1.28' #input('Enter peer IP: ')
        target_port = 666  # int(input('Enter peer port: '))

        sending_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sending_sock.connect((target_ip, target_port))
        print('Connected to peer')

        enc.send_public_key(sending_sock)
        while True:
            #moze nie działac
            data = sending_sock.recv(1024)
            rcv.receive_aes_key(data)
            break

        receive_thread = threading.Thread(target=rcv.receive_messages, args=(sending_sock,))
        receive_thread.start()

    print(rcv.aes_key)
    cipher = AES.new(rcv.aes_key, AES.MODE_ECB)

    while True:
        message = input()

        if message.startswith('SEND'):
            rcv.send_file(sending_sock, message)
        else:
            message = cipher.encrypt(pad(message.encode(), 16))
            sending_sock.send(message)


start_chat()
