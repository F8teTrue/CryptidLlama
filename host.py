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
    # The host creates a socket and binds it to an IP (any in this case) and a port.
    # It then listens for incomming connections and once a client connects it returns a new socket.
    clientIP = "0.0.0.0"
    port = 4000

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((clientIP, port))

    server.listen()
    print(f"Server is listening on port: {port}")

    client, clientAddress = server.accept()
    print(f"Connection from {clientAddress}.")
    print('"exit" to close connection.')

    # Sends own public key to partner and receives partners public key.
    partnerPublicKey = rsa.PublicKey.load_pkcs1(client.recv(1024))
    client.send(publicKey.save_pkcs1("PEM"))

    # This starts 2 threads, 1 for recieving messages and one for sending messages.
    receiveThread = threading.Thread(target = receiveMessage, args=(client, "client"))
    sendThread = threading.Thread(target = sendMessage, args=(client,))

    receiveThread.start()
    sendThread.start()

    # Waits for both threads to finish and closes the sockets after.
    receiveThread.join()
    sendThread.join()

    server.close()
    client.close()

except Exception as e:
    print(f"Error: {str(e)}")
    exit()