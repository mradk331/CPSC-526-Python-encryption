import sys
import socket

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

    # Split the hostname and port number string argument into two variables holding each respectively
    hostport = hostport.split(":")

    hostname = hostport[0]
    port = hostport[1]

    # Convert port string to int
    port = int(port)

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    client_socket.connect((hostname, port))

    client_socket.sendall(cipher.encode("UTF-8"))