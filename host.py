import socket
import threading
import pickle
from colorama import Fore, Style
from Crypto.Cipher import AES 
from secrets import token_bytes
import rsa
from transformers import LlamaForCausalLM, LlamaTokenizer

def AES_encrypt(message, key):
    """
    Encrypts the message using AES.
    """
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce # Generates a random nonce (number used once) to be used in the encryption.
    cipherText, tag = cipher.encrypt_and_digest(message.encode('utf-8')) # Encrypts the message and generates a tag to verify the message in the receiveMessage function.
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
        print(f"{Fore.RED}Message has been tampered with.{Style.RESET_ALL}")
        return False

def receiveMessage(sock, sender):
    """
    Listens continiously for data on the socket, decrypts it using the AES_decrypt function and prints it to the console.
    The message is then given as a prompt to the Llama2 model and the response is encrypted and sent back to the client.
    """
    # Send a message indicating that the model is loading
    message = "Please wait, server is loading Llama2..."
    aes_key = token_bytes(24)
    nonce, cipherText, tag = AES_encrypt(message, aes_key)
    encrypted_aes_key = rsa.encrypt(aes_key, partnerPublicKey)
    data = pickle.dumps((encrypted_aes_key, nonce, cipherText, tag))
    sock.send(data)

    # Load the Llama2 model and tokenizer.
    tokenizer = LlamaTokenizer.from_pretrained("./models/Llama2") # Tokenizer is used to turn string into a format the model can understand.
    model = LlamaForCausalLM.from_pretrained("./models/Llama2").to("cuda").half() # The model is moved to GPU ram and set to half precision to speed up inference.

    # Send a message indicating that the model is ready
    message = "Server is ready."
    aes_key = token_bytes(24)
    nonce, cipherText, tag = AES_encrypt(message, aes_key)
    encrypted_aes_key = rsa.encrypt(aes_key, partnerPublicKey)
    data = pickle.dumps((encrypted_aes_key, nonce, cipherText, tag))
    sock.send(data)

    while True:
        try:
            data = sock.recv(2048)
            # If no data is received, the connection will close.
            if not data:
                print(f'{Fore.RED}Connection with {sender} closed. \n "exit" to close. {Style.RESET_ALL}')
                break
    
            encrypted_AES_key, nonce, cipherText, tag = pickle.loads(data) # Deserialize the byte stream back to a tuple using pickle.
            AES_key = rsa.decrypt(encrypted_AES_key, privateKey) # Decrypts the AES key with own RSA private key.
            message = AES_decrypt(cipherText, nonce, tag, AES_key) # Decrypts the message with the AES key.
            
            # If the message is empty, the connection will close.
            if not message:
                print(f'{Fore.RED}Connection with {sender} closed.{Style.RESET_ALL}')
                break
            print(f"{Fore.GREEN}Received from {sender}{Style.RESET_ALL}: {message}")

            # Use the tokenizer to encode the input message into a format that the model can understand.
            # 'return_tensors' is set to 'pt' to return PyTorch tensors.
            # The tensors are moved to the GPU memory using .to("cuda").
            prompt = tokenizer.encode(message, return_tensors='pt').to("cuda")
            output = model.generate(prompt, max_length = 250, temperature = 0.1) # Generates a response from Llama2. 'temperature' controls the randomness of the output.
            response = tokenizer.decode(output[0], skip_special_tokens = True) # Decodes the output into a string.

            # Encrypts the response and send it back to client.
            AES_key = token_bytes(24)
            nonce, cipherText, tag = AES_encrypt(response, AES_key)
            encrypted_AES_key = rsa.encrypt(AES_key, partnerPublicKey) # Encrypts the AES key with the client's public key

            # Serialize the tuple to a byte stream using pickle, then sends it over the socket.
            data = pickle.dumps((encrypted_AES_key, nonce, cipherText, tag))
            sock.send(data)

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
    # The host creates a socket and binds it to an IP (any in this case) and a port.
    # It then listens for incomming connections and then wait for a client to connect and returns a new socket.

    clientIP = "0.0.0.0"
    port = 4000

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((clientIP, port))

    s.listen()
    print(f"{Fore.GREEN}Server is listening on port{Style.RESET_ALL}: {port}")

    c, c_address = s.accept()
    print(f"{Fore.GREEN}Connection from{Style.RESET_ALL}: {c_address}.")
    print(f'{Fore.YELLOW}"exit" to close connection.{Style.RESET_ALL}')

    # Sends own public key to partner and receives partners public key.
    partnerPublicKey = rsa.PublicKey.load_pkcs1(c.recv(1024))
    c.send(publicKey.save_pkcs1("PEM"))

    # This starts a threads, for receiving prompts from client.
    receiveThread = threading.Thread(target = receiveMessage, args = (c, "client"))

    receiveThread.start()

    # Waits for both threads to finish and closes the sockets after.
    receiveThread.join()
    s.close()
    c.close()

except Exception as e:
    print(f"An error has occured: {str(e)}")
    exit()