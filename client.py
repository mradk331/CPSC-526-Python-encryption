import sys
import socket
import hashlib
import hmac
import random
import string
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

BLOCK_SIZE = 1024

# Function used to encrypt every message sent subsequently after the first message from the client
def encrypt_message(message):

    global cipher
    global cipher_function

    if cipher == "aes128" or cipher == "aes256":
        message = message.encode("UTF-8")

        # Initialize padder
        #padder = padding.PKCS7(128).padder()

        # Initialize the encryptor
        encryptor = cipher_function.encryptor()

        # Pad the message
        #padded_data = padder.update(message.encode("UTF-8"))
        #padded_data += padder.finalize()

        length = 16 - (len(message) % 16)
        message += bytes([length]) * length

        # Encrypt the padded message
        encrypted_message = encryptor.update(message) + encryptor.finalize()

        return encrypted_message

    else:

        # Null cipher so return message
        return message.encode("UTF-8")

# Similar as encrypt but for decryption
def decrypt_message(message):

    global cipher
    global cipher_function

    if cipher == "aes128" or cipher == "aes256":

        # Initialize unpadder
        #unpadder = padding.PKCS7(128).unpadder()

        # Initialize decryptor
        decryptor = cipher_function.decryptor()

        decrypted_data = decryptor.update(message) + decryptor.finalize()
        if message != b'':
            decrypted_data = decrypted_data[:-decrypted_data[-1]]

        #try:
            # Unpad the decrypted data
        #unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

        return decrypted_data.decode("UTF-8")

            # Return decrypted if there is no padding to be unpadded
        #except ValueError:
            #unpadded_data = unpadder.update(decrypted_data)
            #return decrypted_data.decode("UTF-8")

    else:

        # Null cipher so return message
        return message.decode("UTF-8")


def read_file(command, filename, client_socket):

    try:
        message = encrypt_message((command + ":" + filename))
        client_socket.sendall(message)

        # Receive server acknowledgement and file size
        ack_size = client_socket.recv(BLOCK_SIZE)
        ack_size = decrypt_message(ack_size)

        ack_size = ack_size.split(":")

        ack = ack_size[0]

        print("Server response: " + ack)

        # Check if file size received
        if len(ack_size) == 2:

            size_of_file = ack_size[1]
            size_of_file_counter = int(size_of_file)


            file_output = bytearray()

            # Keep reading chunk data from the server and writing it to stdout
            while size_of_file_counter > 0:

                # We don't wanna read in 1024 if there is less than 1024 bytes left
                if size_of_file_counter < BLOCK_SIZE:
                    print("I want to die" + size_of_file + "counter " + str(size_of_file_counter))
                    data_chunk = client_socket.recv(BLOCK_SIZE)
                    data_chunk = decrypt_message(data_chunk)
                    data_chunk = data_chunk.encode("UTF-8")

                else:
                    print("loop")
                    data_chunk = client_socket.recv(BLOCK_SIZE)
                    data_chunk = decrypt_message(data_chunk)
                    data_chunk = data_chunk.encode("UTF-8")

                # Add chunk to a byte array
                file_output.extend(data_chunk)

                # If nothing is read, break out of loop
                if not data_chunk:
                    break

                # Decrease size counter for every 1024 bytes read
                size_of_file_counter -= BLOCK_SIZE

            # Write read data from server to standard output
            sys.stdout.write(file_output.decode(encoding='UTF-8'))

    except socket.error as e:

        print("Server connection closing...")
        quit()


def write_file(command, filename, client_socket):
    global cipher
    try:

        message = encrypt_message((command + ":" + filename))
        client_socket.sendall(message)

        # Receive server acknowledgement
        ack = client_socket.recv(BLOCK_SIZE)
        ack = decrypt_message(ack)
        print("Server response: " + ack)

        #content = sys.stdin.buffer.read(BLOCK_SIZE - 1).decode("UTF-8")
        if cipher != "null":
            content = sys.stdin.buffer.read(BLOCK_SIZE - 1).decode("UTF-8")
            content = encrypt_message(content)
        else:
            content = sys.stdin.buffer.read(BLOCK_SIZE)




        # While the content length read in from stdin is a 1023, keep getting chunk and sending it to the server
        while len(content) == BLOCK_SIZE:
            print("SENDING STUFF HERE \n")
            client_socket.sendall(content)

            if cipher != "null":
                content = sys.stdin.buffer.read(BLOCK_SIZE - 1).decode("UTF-8")
                content = encrypt_message(content)
            else:
                content = sys.stdin.buffer.read(BLOCK_SIZE)



        # Send last block (if any) that is less than a 1024 bytes
        client_socket.sendall(content)

    except socket.error as e:

        print("Server connection closing...")
        quit()


def challenge_response(secret_key, challenge):

    # Encode the key into bytes
    secret_key = secret_key.encode("UTF-8")

    # Takes random challenge string (in bytes) concatenates it with secret key and gets the hash using sha256 hmac
    hmac_hash = hmac.new(secret_key, challenge, digestmod=hashlib.sha256)

    # Get the hash digest
    hash_digest = hmac_hash.hexdigest()

    return hash_digest


# Generates a random string (used for generating the nonce)
def string_generator():

    return ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(16))


if __name__ == "__main__":

    if len(sys.argv) != 6:
        print("Wrong number of arguments provided\n")
        print("USAGE: 'python client.py [command] [filename] [hostname]:[port] [cipher] [key]'")
        quit()

    command = sys.argv[1]
    filename = sys.argv[2]
    hostport = sys.argv[3]
    cipher = sys.argv[4]
    key = sys.argv[5]

    # Check if colon provided to separate hostname and port
    if sys.argv[3].find(":") == -1:
        print("Semi-colon missing\n")
        print("USAGE: 'python client.py [command] [filename] [hostname]:[port] [cipher] [key]'")
        quit()

    if not (command == "read" or command == "write"):
        print("Error: wrong operation given. Operation has to be either read or write")
        quit()

    # Split the hostname and port number string argument into two variables holding each respectively
    hostport = hostport.split(":")

    hostname = hostport[0]
    port = hostport[1]

    # Convert port string to int
    port = int(port)

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    client_socket.connect((hostname, port))

    # Generate a nonce
    nonce = string_generator()

    # Set up the IV and session-key
    init_vector = hashlib.sha256((key + nonce + "IV").encode("UTF-8"))

    # IV has to be 16 bytes
    init_vector = init_vector.hexdigest()
    init_vector = init_vector[:16]

    session_key = hashlib.sha256((key + nonce + "SK").encode("UTF-8"))

    # If cipher used is aes128 we strip the session key to 16 bytes and pass that into the cipher function
    if cipher == "aes128":

        session_key = session_key.hexdigest()
        session_key = session_key[:16]

        # Set up the cipher
        cipher_function = Cipher(algorithms.AES(session_key.encode("UTF-8")), modes.CBC(init_vector.encode("UTF-8")),
                                 backend=default_backend())

    # Otherwise if the cipher is aes256 we strip to 32 bytes
    elif cipher == "aes256":

        session_key = session_key.hexdigest()
        session_key = session_key[:32]
        cipher_function = Cipher(algorithms.AES(session_key.encode("UTF-8")), modes.CBC(init_vector.encode("UTF-8")),
                                 backend=default_backend())

    # Send the cipher and nonce to the server
    client_socket.sendall((cipher + ":" + nonce).encode("UTF-8"))

    # Receive server acknowledgement
    ack = client_socket.recv(BLOCK_SIZE)
    ack = decrypt_message(ack)
    print("Server response: " + ack)

    # Get the random string challenge from the server and create a response
    challenge = client_socket.recv(BLOCK_SIZE)
    challenge = challenge.strip()

    challenge = decrypt_message(challenge)

    print("CHALLENGE: " + challenge)

    digest_response = challenge_response(key, challenge.encode("UTF-8"))
    digest_response = encrypt_message(digest_response)

    # Send the response back to the server
    client_socket.sendall(digest_response)

    # Receive authentication success or failure
    authentication_response = client_socket.recv(BLOCK_SIZE)

    authentication_response = decrypt_message(authentication_response)

    print("Server authentication response: " + authentication_response)

    # Send the filename and the operation we wish to do upon it to the server
    if command == "write":

        write_file(command, filename, client_socket)

    else:

        read_file(command, filename, client_socket)

    final_message = client_socket.recv(BLOCK_SIZE)

    final_message = decrypt_message(final_message)

    print(final_message)

    client_socket.close()