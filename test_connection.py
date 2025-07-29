import socket
import time

def test_connection():
    # Create socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Set a timeout for operations
    s.settimeout(15)
    
    try:
        # Connect to the server
        print("Connecting to localhost:9999...")
        s.connect(('localhost', 9999))
        print("Connected successfully!")
        
        # Wait a moment for the server to prepare the warning
        time.sleep(0.5)
        
        # Try to receive the warning message
        print("Waiting for warning message...")
        total_data = b""
        
        # Loop to receive all data
        while True:
            try:
                s.settimeout(2)
                chunk = s.recv(1024)
                if not chunk:  # If no data received, break
                    if not total_data:
                        print("No data received.")
                    break
                
                total_data += chunk
                print(f"Received chunk of {len(chunk)} bytes")
                
                # If we've received enough data or there's a delay, stop
                if len(total_data) > 0 and not chunk:
                    break
                    
            except socket.timeout:
                break  # Break on timeout
        
        # Print the warning message if received
        if total_data:
            print("\nReceived warning message:")
            print("-" * 50)
            print(total_data.decode('utf-8'))
            print("-" * 50)
            
        # Send a test message back
        test_message = "This is a test intrusion"
        s.send(test_message.encode('utf-8'))
        print(f"Sent test message: {test_message}")
            
    except socket.timeout:
        print("Connection timed out")
    except ConnectionRefusedError:
        print("Connection refused - is the server running?")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        # Close the socket
        print("Closing connection...")
        s.close()
        print("Connection closed.")

if __name__ == "__main__":
    test_connection() 