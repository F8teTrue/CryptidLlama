import socket
import threading
import pickle
from Crypto.Cipher import AES
from secrets import token_bytes
import rsa

def AES_encrypt(message, key):
    '''
    Encrypts the message using AES.
    '''
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    cipherText, tag = cipher.encrypt_and_digest(message.encode("utf-8"))
    return cipherText, nonce, tag

def AES_decrypt(cipherText, nonce, tag, key):
    '''
    Decrypts the message using AES.
    '''
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    message = cipher.decrypt(cipherText)
    try:
        cipher.verify(tag)
        return message.decode("utf-8")
    except:
        print(f"Message has been tampered with.")
        return False

def sendMessage(sock):
    '''
    Takes user input, encrypts it with the AES_encrypt function and sends it to the connected socket.
    '''
    while True:
        message = input()
        if message.lower() == "exit":
            print(f"Closing connection")
            break

        if not message.strip():
            print(f"Message cannot be empty.")
            continue
        
        AES_key = token_bytes(16)
        cipherText, nonce, tag = AES_encrypt(message, AES_key)
        encrypted_AES_key = rsa.encrypt(AES_key, partnerPublicKey)

        data = pickle.dumps((encrypted_AES_key, cipherText, nonce, tag))
        sock.send(data)

    sock.close()

def receiveMessage(sock, sender):
    '''
    Listens continiously for data on the socket, decrypts it using the AES_decrypt function and prints it to the console.
    '''
    while True:
        data = sock.recv(1024)
        if not data:
            print(f"Closing connection.")
            break

        encrypted_AES_key, cipherText, nonce, tag = pickle.loads(data)
        AES_key = rsa.decrypt(encrypted_AES_key, privateKey)
        message = AES_decrypt(cipherText, nonce, tag, AES_key)

        if not message:
            print(f"Connection with {sender} has been closed.")
            break
        print(f"Received from {sender}: {message}")
        
    sock.close()

publicKey, privateKey = rsa.newkeys(1024) # Generate a RSA key pair.
partnerPublicKey = None

try:
    # The client creates a socket and connects to the host using the hosts IP and the chosen port.
    serverIP = "10.58.177.74"
    port = 4000

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((serverIP, port))

    print(f"Connected to {serverIP} on port:{port}")
    print(f'"exit" to close connection.')

    client.send(publicKey.save_pkcs1("PEM"))
    partnerPublicKey = rsa.PublicKey.load_pkcs1(client.recv(1024))

    # This starts 2 threads, 1 for recieving messages and one for sending messages.
    receiveThread = threading.Thread(target = receiveMessage, args=(client, "server"))
    sendThread = threading.Thread(target = sendMessage, args=(client,))

    receiveThread.start()
    sendThread.start()
                                  
except Exception as e:
    print(f"Error: {str(e)}")
    exit()