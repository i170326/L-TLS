import socket
import sys
import hashlib
from Crypto.Cipher import AES
from ecdsa import VerifyingKey, BadSignatureError
import pyDH
from Crypto.Cipher import AES

class CA:
    def verifyCert(sign):
        with open("public.pem") as f:
            vk = VerifyingKey.from_pem(f.read())
        message=b"VERIFIED"
        with open("signature", "rb") as f:
            sig = f.read()
        try:
            vk.verify(sig, message)
            print ("good signature")
            return 1
        except BadSignatureError:
            print ("BAD SIGNATURE")
            return 0

def tcp_connect(ip,port):
    sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((socket.gethostname(),port))
    return sock

def tcp_receive(sock):
    msg = sock.recv(5000).decode("utf-8")
    return msg

def tcp_send(msg,conn):
    #print("Sending message")
    conn.sendall(bytes(msg,"utf-8"))

def tcp_send_cipher(msg,conn):
    #print("Sending message")
    conn.sendall(msg)

def tcp_receive_cipher(sock):
    msg = sock.recv(5000)
    return msg

def tcp_close(conn):
    print("Closing connection")
    conn.close()

while True:
    print("Connecting to server")
    sock=tcp_connect('locahost',8001)
    print("Connected\n")

    tcp_send("HELLO",sock)


    recvMsg=tcp_receive(sock)
    if(len(recvMsg)>0):
        print(recvMsg)
        cert=tcp_receive_cipher(sock)
        if(len(cert)>0):
            if(not CA.verifyCert(cert)):
                break
    server_pubkey=tcp_receive_cipher(sock)
    print("pubkey received")
    d2 = pyDH.DiffieHellman()
    pubkey=d2.gen_public_key()
    #privkey=d2.gen_private_key()
    sharedkey = d2.gen_shared_key(int(server_pubkey))

    tcp_send(sharedkey.to_string(),sock)

    obj = AES.new(sharedkey.encode("utf8"), AES.MODE_CBC, 'This is an IV456'.encode("utf8"))

    recvMsg=tcp_receive(sock)
    if(len(recvMsg)>0):
        print(obj.decrypt(recvMsg))
    
    if(obj.decrypt(recvMsg)=="FINISHED"):
        print("Handshake Successful")



    
        
    

        