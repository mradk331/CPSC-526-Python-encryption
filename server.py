import sys
import socket
import hashlib
import random
import string
import hmac
import os
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

BLOCK_SIZE = 1024

def request(client_socket):

    # Receive the filename and operation
    fileop = client_socket.recv(BLOCK_SIZE)

    fileop = decrypt_message(fileop)
    fileop = fileop.strip()


    fileop = fileop.split(":")

    operation = fileop[0]
    filename = fileop[1]

    # Check if operation and filename are valid
    if operation == "read":

        if not os.path.isfile(filename):

            print("Error: file client is trying to read does not exist. Disconnecting client.")
            message = encrypt_message(("Error, the file " + filename
                                       + " you are trying to read does not exist. Disconnecting..."))
            client_socket.sendall(message)
            client_socket.close()

        else:

            # Send file-size to client
            file_size = os.stat(filename).st_size
            file_size = str(file_size)

            message = encrypt_message(("Success, read operation proceeding." + ":" + file_size))
            client_socket.sendall(message)

            # Delay sending the file chunks so as to not send the above success, filesize along with
            # a part of a file chunk
            time.sleep(0.2)

            data_exchange(client_socket, operation, filename)

    elif operation == "write":

        # Indicate success
        message = encrypt_message("Success, write operation proceeding.")
        client_socket.sendall(message)

        time.sleep(0.2)

        data_exchange(client_socket, operation, filename)

    else:
        # Operation does not exist
        print("Operation request: " + operation+ " on file " + filename + " does not exist. Disconnecting client.")
        message = encrypt_message(("Error, operation " + operation + " you are trying to perform on " + filename + " does not exist. Disconnecting..."))
        client_socket.sendall(message)

        client_socket.close()


def data_exchange(client_socket, operation, filename):

    if operation == "read":

        # Open the file, read chunks, encrypt and send them to the client
        file = open(filename, 'rb')
        line = file.read(BLOCK_SIZE - 1)

        while line:

            message = encrypt_message(line.decode("UTF-8"))
            client_socket.sendall(message)

            # Read next line in file
            line = file.read(BLOCK_SIZE - 1)

        # Close file
        file.close()
        time.sleep(.1)
        print("Operation successful. Disconnecting from client.")
        message = encrypt_message((operation + " operation successful. Disconnecting..."))
        client_socket.sendall(message)
        client_socket.close()

    # Otherwise we write to server from client side
    else:

        file_size = 0

        # Get hard drive statistics (such as disk space) from current directory
        stats = os.statvfs('/')

        # disk size in bytes = (block size of file system * available number of blocks to the user) / 1024
        # This is the disk size for the current directory
        disk_size = (stats.f_frsize * stats.f_bavail) / BLOCK_SIZE

        # We open file with filename and keep writing received chunks of data to it
        with open(filename, 'wb') as file:

            # Guarantees receive will never block indefinitely
            #client_socket.setblocking(0)


            write_chunk = client_socket.recv(BLOCK_SIZE)
            decrypt_chunk = decrypt_message(write_chunk)

            while len(write_chunk) == BLOCK_SIZE:

                # If nothing is read, break out of the loop

                print("WRITE CHUNK: " + decrypt_chunk)

                chunk_length = len(write_chunk) #might be write, too tired

                file_size += chunk_length

                # Write to file on disk
                if file_size < disk_size:
                    print("122112312312312312313" + str(len(write_chunk)))
                    file.write(decrypt_chunk.encode("UTF-8"))
                    write_chunk = client_socket.recv(BLOCK_SIZE)
                    decrypt_chunk = decrypt_message(write_chunk)
                    print("HERERERERRERER " + str(len(write_chunk)))
                # If the file we are reading in becomes larger
                # than or equal to the available disk size, indicate error and disconnect
                else:

                    print("Error: client trying to write a file that is larger "
                            "than the available disk size. Disconnecting client.")

                    message = encrypt_message("Error, you are trying to upload a file that "
                                                "is larger than the available server disk size. Disconnecting...")

                    client_socket.sendall(message)

                    client_socket.close()

            if file_size < disk_size:
                print("Last WRITE CHUNK: " + decrypt_chunk)

                file.write(decrypt_chunk.encode("UTF-8"))


            # If zero bytes being written, it will still create a zero
            # bytes file but setblock will throw an exception on receive
            # on receive
            print("FUCING ERRRORSRSRSRSRSRSRSRSR")


        file.close()
        #can't send too fast to client
        time.sleep(.1)
        print("Operation successful. Disconnecting from client.")
        message = encrypt_message((operation + " operation successful. Disconnecting..."))
        client_socket.sendall(message)
        client_socket.close()

# Function used to encrypt every message sent subsequently after the first message to the client
def encrypt_message(message):

    global cipher
    global cipher_function

    if cipher == "aes128" or cipher == "aes256":

        message = message.encode("UTF-8")

        # Initialize padder
        #padder = padding.PKCS7(128).padder()

        # Initialize the encryptor
        encryptor = cipher_function.encryptor()

        length = 16 - (len(message) % 16)
        message += bytes([length]) * length
        print("kill me " + str(len(message)))
        # Pad the message
        #padded_data = padder.update(message.encode("UTF-8"))
        #padded_data += padder.finalize()

        # Encrypt the padded message
        encrypted_message = encryptor.update(message) + encryptor.finalize()

        return encrypted_message

    else:

        # Null cipher so return message
        return message.encode("UTF-8")


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

        #return decrypted_data.decode("UTF-8")

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


# Generates a random string
def string_generator():

    return ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(32))


def authentication(secret_key, client_socket):

    authenticated = False

    # Generate a 32 byte random string challenge
    random_string = string_generator()

    # Encrypt the random string message
    encrypted_message = encrypt_message(random_string)

    # Encode the secret key
    secret_key = secret_key.encode("UTF-8")

    # Delay sending the challenge by .2 seconds in the case of receiving the challenge with the previous success ack
    time.sleep(0.2)

    # Send the random string challenge to the client
    client_socket.sendall(encrypted_message)

    # Receive an encrypted SHA256 HMAC hexadecimal digest challenge response by the client
    response = client_socket.recv(BLOCK_SIZE)

    # Decrypt the response
    response = decrypt_message(response)

    # Strip of any special characters
    response = response.strip()

    print("RESPONSE: " + response)

    # We hash the server secret key with the same random_string and obtain the hexadecimal digest
    secret_key_hash = hmac.new(secret_key, msg=random_string.encode("UTF-8"), digestmod=hashlib.sha256)

    # Obtain hex-digest
    secret_key_digest = secret_key_hash.hexdigest()
    print("SECRET KEY DIGEST: " + secret_key_digest)

    # If the digest we computed is the same as the one provided by the response of the client, then the client has the
    # correct secret key
    if secret_key_digest == response:

        # Send success to client
        success_message = encrypt_message("Successfully authenticated")

        client_socket.sendall(success_message)

        # Client is now authenticated
        authenticated = True

        return authenticated

    else:

        failure_message = encrypt_message("Error: Wrong key. Disconnecting...")

        client_socket.sendall(failure_message)

        # Disconnect the client
        client_socket.close()

        return authenticated


if __name__ == "__main__":

    HOST = "localhost"

    if len(sys.argv) != 3:
        print("Error: Wrong number of arguments provided\n")
        print("USAGE: 'python server.py [port] [key]'")
        quit()

    port = sys.argv[1]
    key = sys.argv[2]

    print("Listening on port: " + port)
    print("Using secret key: " + key)

    # Convert port string to int
    port = int(port)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the source hostname and the source port number
    server_socket.bind((HOST, port))

    # Listen to incoming messages
    server_socket.listen(5)

    # We keep looping and accepting client connection
    while 1:

        (client_socket, client_address) = server_socket.accept()

        data = client_socket.recv(BLOCK_SIZE)

        data = data.decode("UTF-8")

        data = data.split(":")

        if len(data) != 2:
            print("Error: Cipher or nonce not provided. Disconnecting client.")

            client_socket.sendall("Error: cipher or nonce not provided. Disconnecting...".encode("UTF-8"))
            client_socket.close()
        else:
            cipher = data[0].lower()
            nonce = data[1]

            # Set up the IV and session-key
            init_vector = hashlib.sha256((key + nonce + "IV").encode("UTF-8"))

            # IV has to be 16 bytes
            init_vector = init_vector.hexdigest()
            init_vector = init_vector[:16]

            session_key = hashlib.sha256((key + nonce + "SK").encode("UTF-8"))

            print("CIPHER: " + cipher)
            # Check if incorrect cipher was provided
            if cipher != "aes128" and cipher != "aes256" and cipher != "null":
                print("Error: Invalid cipher provided. Disconnecting client.")
                client_socket.sendall(("Error " + cipher + " is not supported. Disconnecting...").encode("UTF-8"))
                client_socket.close()

            else:

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

                # Indicate success to user
                success = encrypt_message("Success\n")
                client_socket.sendall(success)

                # Authenticate the client
                authenticated = authentication(key, client_socket)

                # If the client is authenticated, get the file request
                if authenticated:

                    request(client_socket)

                else:
                    print("Client was not authenticated. Secret keys not matching.")