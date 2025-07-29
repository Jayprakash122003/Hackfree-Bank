import socket
import threading
import datetime

HOST = '0.0.0.0'  # Listen on all interfaces
PORT = 9999       # Port to listen on

def current_time():
    """Get the current time string"""
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def handle_client(client_socket, client_address):
    """Handle a client connection and immediately send a warning"""
    timestamp = current_time()
    client_ip, client_port = client_address
    
    print(f"[{timestamp}] New connection from {client_ip}:{client_port}")
    
    # Prepare warning message
    warning = (
        "WARNING: Unauthorized access detected. This connection attempt has been logged and "
        "reported to security personnel. Your IP address and details have been recorded.\r\n"
    )
    
    # Send the warning message
    try:
        print(f"[{timestamp}] Sending warning to {client_ip}:{client_port}")
        client_socket.sendall(warning.encode('utf-8'))
        print(f"[{timestamp}] Warning sent successfully to {client_ip}:{client_port}")
    except Exception as e:
        print(f"[{timestamp}] Failed to send warning to {client_ip}:{client_port}: {e}")
    
    # Wait for any data from client
    try:
        client_socket.settimeout(5)
        data = client_socket.recv(1024)
        if data:
            try:
                decoded = data.decode('utf-8').strip()
                print(f"[{timestamp}] Received from {client_ip}:{client_port}: {decoded}")
            except:
                print(f"[{timestamp}] Received binary data from {client_ip}:{client_port}")
    except socket.timeout:
        print(f"[{timestamp}] Connection timed out: {client_ip}:{client_port}")
    except Exception as e:
        print(f"[{timestamp}] Error receiving data: {e}")
    
    # Close the socket
    try:
        client_socket.close()
        print(f"[{timestamp}] Closed connection from {client_ip}:{client_port}")
    except Exception as e:
        print(f"[{timestamp}] Error closing socket: {e}")

def main():
    """Main function to start the server"""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind((HOST, PORT))
        server.listen(5)
        
        print("="*50)
        timestamp = current_time()
        print(f"[{timestamp}] Simple Intrusion Monitor started")
        print(f"[{timestamp}] Listening on {HOST}:{PORT}")
        print("="*50)
        
        while True:
            client_socket, address = server.accept()
            
            client_handler = threading.Thread(
                target=handle_client,
                args=(client_socket, address)
            )
            client_handler.daemon = True
            client_handler.start()
            
    except KeyboardInterrupt:
        print("\nShutting down server...")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        server.close()

if __name__ == "__main__":
    main() 