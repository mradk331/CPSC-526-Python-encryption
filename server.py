import sys
import socket


if __name__ == "__main__":

    HOST = "localhost"

    if len(sys.argv) != 3:
        print("Wrong number of arguments provided\n")
        print("USAGE: 'python server.py [port] [key]'")
        quit()

    port = sys.argv[1]
    key = sys.argv[2]

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

        data = client_socket.recv(1024)

        data = data.decode("UTF-8")

        print("DATA: " + data)
