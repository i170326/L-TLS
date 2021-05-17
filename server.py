import socket
import sys
import string
import random
from Crypto.Cipher import AES
import pyDH
from Crypto.Cipher import AES
from ecdsa import SigningKey


class CA:
    def getCertificate():
        with open("private.pem") as f:
            sk = SigningKey.from_pem(f.read())
        message=b"VERIFIED"
        sig = sk.sign(message)
        print("Signed")
        with open("signature", "wb") as f:
            f.write(sig)
        return sig

def tcp_connect(ip,port):
    sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((socket.gethostname(),port))
    print("Server is listening")
    sock.listen(5)
    return sock

def tcp_send(msg,conn):
    #print("Sending message")
    conn.send(bytes(msg,"utf-8"))

def tcp_receive(sock):
    #time.sleep(10)
    msg = sock.recv(5000).decode("utf-8")
    """while True:
        msg = sock.recv(8)
        if len(msg) <=0:
            break
        full_msg = full_msg + msg.decode("utf-8")
    return full_msg"""
    return msg

def tcp_receive_cipher(sock):
    msg = sock.recv(5000)
    return msg

def tcp_send_cipher(msg,conn):
    #print("Sending message")
    conn.sendall(msg)

def tcp_close(conn):
    print("Closing connection")
    conn.close()

sock=tcp_connect('localhost',8001) #Setting up server
while True:
    print("Waiting for connection\n")
    conn, address = sock.accept()
    print("Connection has been established with: ",address,"\n")

    recvMsg = tcp_receive(conn)
    print("Client Hello Received")

    cert=CA.getCertificate()

    d1 = pyDH.DiffieHellman()
    pubkey=d1.gen_public_key()
    #privkey=d1.gen_private_key()

    tcp_send("HELLO",conn)
    tcp_send_cipher(cert,conn)
    tcp_send_cipher(str(pubkey).encode('utf-8'),conn)
    print("pubkey sent")

    sharedkey=tcp_receive(conn)

    obj = AES.new(sharedkey.encode("utf-8"), AES.MODE_CBC, 'This is an IV456'.encode("utf8"))
    msg=obj.encrypt("FINISHED")
    tcp_send(msg,conn)














