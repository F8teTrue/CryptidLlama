import socket
import threading
import pickle
from Crypto.Cipher import AES
from secrets import token_bytes


def sendMessage(sock):
    while True:
        message = input()
        if message.lower() == "exit":
            print(f"Closing connection")
            break

        if not message.strip():
            print(f"Message cannot be empty.")
            continue
        
        sock.send(message.encode("utf-8"))

    sock.close()

def receiveMessage(sock, sender):
    while True:
        data = sock.recv(1024)
        if not data:
            print(f"Closing connection.")
            break
        
        message = data.decode("utf-8")

        if not message:
            print(f"Connection with {sender} has been closed.")
            break
        print(f"Received from {sender}: {message}")

    sock.close()

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

    receiveThread = threading.Thread(target = receiveMessage, args=(client, "client"))
    sendThread = threading.Thread(target = sendMessage, args=(client,))

    receiveThread.start()
    sendThread.start()

    receiveThread.join()
    sendThread.join()

    server.close()
    client.close()

except Exception as e:
    print(f"Error: {str(e)}")
    exit()