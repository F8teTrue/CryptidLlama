import socket
import threading
from Crypto.Cipher import AES
from secrets import token_bytes


def sendMessage(sock):
    while True:
        message = input()
        if message.lower() == "exit":
            print(f"Closing connection")
            break

        sock.send(message.encode("utf-8"))
    sock.close()

def receiveMessage(sock, sender):
    while True:
        data = sock.recv(1024)
        if not data:
            print(f"Closing connection.")
            break

        message = data.decode("utf-8")

        print(f"Received from {sender}: {message}")
    sock.close()

try:
    # The client creates a socket and connects to the host using the hosts IP and the chosen port.
    serverIP = "10.58.177.74"
    port = 4000

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((serverIP, port))

    print(f"Connected to {serverIP} on port:{port}")
    print(f'"exit" to close connection.')

    receiveThread = threading.Thread(target = receiveMessage, args=(client, "server"))
    sendThread = threading.Thread(target = sendMessage, args=(client,))

    receiveThread.start()
    sendThread.start()
    
                                  
except Exception as e:
    print(f"Error: {str(e)}")
    exit()