import socket
import threading
import time

def handle_client(client_socket, client_address):
    """Handle a client connection"""
    print(f"Connection from {client_address[0]}:{client_address[1]}")
    
    # Send warning message
    warning_message = "WARNING: Unauthorized access detected. This connection attempt has been logged.\r\n"
    try:
        print(f"Sending warning to {client_address[0]}:{client_address[1]}")
        client_socket.sendall(warning_message.encode('utf-8'))
        print(f"Warning sent to {client_address[0]}:{client_address[1]}")
    except Exception as e:
        print(f"Error sending warning: {e}")
    
    # Wait for data
    try:
        client_socket.settimeout(10)
        data = client_socket.recv(1024)
        if data:
            print(f"Received from {client_address[0]}:{client_address[1]}: {data.decode('utf-8')}")
    except socket.timeout:
        print(f"Connection from {client_address[0]}:{client_address[1]} timed out")
    except Exception as e:
        print(f"Error receiving data: {e}")
    
    # Close the connection
    print(f"Closing connection from {client_address[0]}:{client_address[1]}")
    client_socket.close()

def run_server():
    """Run a simple TCP server that sends a warning message to every connection"""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    # Bind to all interfaces on port 9999
    server_address = ('0.0.0.0', 9999)
    print(f"Starting server on {server_address[0]}:{server_address[1]}")
    server.bind(server_address)
    
    # Listen for incoming connections
    server.listen(5)
    print("Server is listening for connections...")
    
    try:
        while True:
            # Accept a connection
            client_socket, client_address = server.accept()
            
            # Handle the client in a new thread
            client_thread = threading.Thread(
                target=handle_client,
                args=(client_socket, client_address)
            )
            client_thread.daemon = True
            client_thread.start()
    
    except KeyboardInterrupt:
        print("\nShutting down server...")
    finally:
        server.close()

if __name__ == "__main__":
    run_server() 