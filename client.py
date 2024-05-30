import socket
import threading
import pickle
from colorama import Fore, Style
import sys, time
from Crypto.Cipher import AES 
from secrets import token_bytes
import rsa

def AES_encrypt(message, key):
    """
    Encrypts the message using AES.
    """
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce # Generates a random nonce (number used once) to be used in the encryption.
    cipherText, tag = cipher.encrypt_and_digest(message.encode("utf-8")) # Encrypts the message and generates a tag to verify the message in the receiveMessage function.
    return nonce, cipherText, tag 

def AES_decrypt(cipherText, nonce, tag, key):
    """
    Decrypts the message using AES.
    """
    cipher = AES.new(key, AES.MODE_EAX, nonce = nonce)
    message = cipher.decrypt(cipherText) # Decrypts the message and generates a tag to verify the message.
    try:
        cipher.verify(tag) # Verifies the tag by checking if it matches the tag generated in the encryption.
        return message.decode('utf-8') # If the tags match, the message is decoded from bytes to a string and returned.
    except:
        # If the tags do not match, the message has been tampered with and False is returned.
        print("Message has been tampered with.") 
        return False

def print_slow(str):
    """
    Prints a string character by character with a delay of 0.03 seconds.
    """
    for letter in str:
        sys.stdout.write(letter)
        sys.stdout.flush()
        time.sleep(0.03)
    
def sendMessage(sock):
    """
    Takes user input, encrypts it with the AES_encrypt function and sends it to the connected socket.
    """
    while True:
        try:
            message = input("")
            # If the message is "exit", the connection will close.
            if message.lower() == "exit":
                print(f"{Fore.RED}Connection closing.{Style.RESET_ALL}")
                sock.close()
                break
            
            # Checks if the message is empty.
            if not message.strip():
                print(f"{Fore.YELLOW}Message cannot be empty.{Style.RESET_ALL}")
                sys.stdout.write("-> ")
                sys.stdout.flush()
                continue
            
            # Creates a new AES key for each message and encrypts the message with it.
            AES_key = token_bytes(24)
            nonce, cipherText, tag = AES_encrypt(message, AES_key)
            encrypted_AES_key = rsa.encrypt(AES_key, partnerPublicKey) # Encrypts the AES key with the host's public key.

            # Serialize the tuple to a byte stream using pickle, then sends it over the socket.
            data = pickle.dumps((encrypted_AES_key, nonce, cipherText, tag))
            sock.send(data)

        # If an error occurs, the connection will close.
        except OSError as e:
            if e.errno == 9:
                print(f"{Fore.RED}An error has occured: Connection with server closed. \n 'exit' to close.{Style.RESET_ALL}")
                break
    sock.close()

def receiveMessage(sock, sender):
    """
    Listens continiously for data on the socket, decrypts it using the AES_decrypt function and prints it to the console.
    """

    first_message = True
    while True:
        try:
            data = sock.recv(2048)
            # If no data is received, the connection will close.
            if not data:
                print(f'Connection with {sender} closed. \n "exit" to close.')
                break
    
            encrypted_AES_key, nonce, cipherText, tag = pickle.loads(data) # Deserialize the byte stream back to a tuple using pickle.
            AES_key = rsa.decrypt(encrypted_AES_key, privateKey) # Decrypts the AES key with own RSA private key.
            message = AES_decrypt(cipherText, nonce, tag, AES_key) # Decrypts the message with the AES key.
            
            # If the message is empty, the connection will close.
            if not message:
                print(f'{Fore.RED}Connection with {sender} closed.{Style.RESET_ALL}')
                break
            print_slow(f"{Fore.GREEN}\nReceived from {sender}{Style.RESET_ALL}: {message}")
            print("\n","-" * 80)
            if not first_message or "Server is ready." in message:
                print("-> ", end="")
                sys.stdout.flush()
            first_message = False

        # If an error occurs, the connection will close.
        except rsa.DecryptionError:
            print(f"{Fore.RED}DECRYPTION ERROR! Press ctrl + c to exit.{Style.RESET_ALL}")
            break
        except OSError as e:
            if e.errno == 9:
                break
            elif e.errno == 10054:
                print(f'{Fore.RED}Connection with {sender} has been closed.{Style.RESET_ALL}')
                break
            elif e.errno == 10053:
                print(f'{Fore.RED}Connection with {sender} has been closed.{Style.RESET_ALL}')
                break
            else:
                raise e
        except KeyboardInterrupt:
            print(f'{Fore.RED}Connection closed.{Style.RESET_ALL}')
            break
    sock.close()

publicKey, privateKey = rsa.newkeys(1024) # Generates a RSA key pair.
partnerPublicKey = None

try:
    # The client creates a socket and connects to the host using the hosts IP and the chosen port.
    serverIP = "10.58.177.74"
    port = 4000

    c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    c.connect((serverIP, port))

    print(f"{Fore.GREEN}Connected to {serverIP} on port: {port}{Style.RESET_ALL}")
    print(f'{Fore.YELLOW}"exit" to close connection.{Style.RESET_ALL}')

    # Receives partners public key and sends own public key to partner.
    c.send(publicKey.save_pkcs1("PEM"))
    partnerPublicKey = rsa.PublicKey.load_pkcs1(c.recv(1024))

    # This starts 2 threads, 1 for recieving messages and one for sending messages.
    receiveThread = threading.Thread(target = receiveMessage, args = (c, "server"))
    sendThread = threading.Thread(target = sendMessage, args = (c,))

    receiveThread.start()
    sendThread.start()

except Exception as e:
    print(f"{Fore.RED}An error has occured: {str(e)}{Style.RESET_ALL}")
    exit()