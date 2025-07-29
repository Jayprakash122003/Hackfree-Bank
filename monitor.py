import socket
import threading
import datetime
import os
import json
import sys
import time
import traceback
import signal

# Configuration
HOST = '0.0.0.0'  # Listen on all available interfaces
PORT = 9999       # Port to listen on
SECURITY_LOG_FILE = 'logs/security.log'  # Security log file
INTRUSION_LOG_FILE = 'intrusion_log.txt' # Intrusion log file (text format)
INTRUSION_JSON_FILE = 'intrusion_log.json' # Intrusion JSON log file
MAX_CONNECTIONS = 10
BUFFER_SIZE = 1024

class IntrusionMonitor:
    def __init__(self, host=HOST, port=PORT, security_log_file=SECURITY_LOG_FILE, 
                 intrusion_log_file=INTRUSION_LOG_FILE, intrusion_json_file=INTRUSION_JSON_FILE):
        self.host = host
        self.port = port
        self.security_log_file = security_log_file
        self.intrusion_log_file = intrusion_log_file
        self.intrusion_json_file = intrusion_json_file
        self.server_socket = None
        self.running = False
        self.connections = []
        
        # Ensure log file directories exist
        self._ensure_log_directories()
        
        # Clear existing logs when starting
        self._initialize_log_files()
    
    def _ensure_log_directories(self):
        """Ensure all log directories exist"""
        security_log_dir = os.path.dirname(self.security_log_file)
        if security_log_dir and not os.path.exists(security_log_dir):
            os.makedirs(security_log_dir)
    
    def _initialize_log_files(self):
        """Initialize log files, clearing any existing content"""
        # Initialize security log file
        with open(self.security_log_file, 'w') as f:
            f.write("# HackFreeBank Security Log\n")
            f.write("# Format: [TIMESTAMP] - IP:PORT - ACTION - DATA\n\n")
        
        # Initialize intrusion log file
        with open(self.intrusion_log_file, 'w') as f:
            f.write("# HackFreeBank Intrusion Log\n")
            f.write("# Format: [YYYY-MM-DD HH:MM:SS] Connection attempt from IP:PORT - Message\n\n")
        
        # Initialize JSON log file
        with open(self.intrusion_json_file, 'w') as f:
            f.write("[]")  # Initialize with empty JSON array
    
    def start(self):
        """Start the intrusion monitoring server"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(MAX_CONNECTIONS)
            
            self.running = True
            timestamp = self.get_formatted_timestamp()
            print(f"[{timestamp}] Intrusion Monitor started on {self.host}:{self.port}")
            self.log_event('SYSTEM', 'Intrusion Monitor started')
            
            # Start acceptor thread
            acceptor_thread = threading.Thread(target=self._accept_connections)
            acceptor_thread.daemon = True
            acceptor_thread.start()
            
            # Keep the main thread alive
            try:
                while self.running:
                    time.sleep(1)
            except KeyboardInterrupt:
                self.stop()
                
        except socket.error as e:
            timestamp = self.get_formatted_timestamp()
            print(f"[{timestamp}] Socket error: {e}")
            self.log_event('ERROR', f"Socket error: {e}")
        except Exception as e:
            timestamp = self.get_formatted_timestamp()
            print(f"[{timestamp}] Error starting monitor: {e}")
            self.log_event('ERROR', f"Error starting monitor: {e}")
            traceback.print_exc()
    
    def stop(self):
        """Stop the intrusion monitoring server"""
        self.running = False
        
        # Close all client connections
        for conn in self.connections:
            try:
                conn.close()
            except:
                pass
        
        # Close server socket
        if self.server_socket:
            self.server_socket.close()
        
        timestamp = self.get_formatted_timestamp()
        print(f"[{timestamp}] Intrusion Monitor stopped")
        self.log_event('SYSTEM', 'Intrusion Monitor stopped')
    
    def _accept_connections(self):
        """Accept incoming connections and handle them in separate threads"""
        while self.running:
            try:
                client_socket, client_address = self.server_socket.accept()
                self.connections.append(client_socket)
                
                # Get formatted timestamp
                timestamp = self.get_formatted_timestamp()
                
                # Log the connection attempt
                print(f"[{timestamp}] Connection attempt from {client_address[0]}:{client_address[1]}")
                self.log_event(f"{client_address[0]}:{client_address[1]}", 'CONNECTION_ATTEMPT')
                
                # Log to intrusion_log.txt with format
                self.log_intrusion(f"{client_address[0]}:{client_address[1]}", "Connection attempt detected")
                
                # Log to JSON file
                self.log_intrusion_json(client_address[0], timestamp, "Connection Attempt")
                
                # Handle the connection in a new thread
                client_thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_socket, client_address)
                )
                client_thread.daemon = True
                client_thread.start()
                
            except socket.error as e:
                if self.running:  # Only log if we're still supposed to be running
                    timestamp = self.get_formatted_timestamp()
                    print(f"[{timestamp}] Socket accept error: {e}")
                    self.log_event('ERROR', f"Socket accept error: {e}")
            except Exception as e:
                if self.running:
                    timestamp = self.get_formatted_timestamp()
                    print(f"[{timestamp}] Error accepting connection: {e}")
                    self.log_event('ERROR', f"Error accepting connection: {e}")
                    traceback.print_exc()
    
    def _handle_client(self, client_socket, client_address):
        """Handle client connection and respond with warning"""
        client_ip, client_port = client_address
        timestamp = self.get_formatted_timestamp()
        
        # Send warning message with proper line endings
        warning_message = (
            "WARNING: Unauthorized access detected. This connection attempt "
            "has been logged and reported to security personnel. "
            "Your IP address and connection details have been recorded.\r\n"
        )
        
        try:
            # Send warning message immediately
            print(f"[{timestamp}] Sending warning to {client_ip}:{client_port}")
            client_socket.sendall(warning_message.encode('utf-8'))
            
            # Log warning sent
            print(f"[{timestamp}] Warning sent to {client_ip}:{client_port}")
            self.log_event(f"{client_ip}:{client_port}", 'WARNING_SENT')
            self.log_intrusion(f"{client_ip}:{client_port}", "Warning sent to intruder")
            self.log_intrusion_json(client_ip, timestamp, "Warning Sent")
        except Exception as e:
            timestamp = self.get_formatted_timestamp()
            print(f"[{timestamp}] Failed to send warning: {e}")
            self.log_event(f"{client_ip}:{client_port}", 'WARNING_FAILED', str(e))
            
        try:
            # Set a timeout for receiving data
            client_socket.settimeout(10)
            
            # Receive data from the client
            data = client_socket.recv(BUFFER_SIZE)
            if data:
                # Get formatted timestamp
                timestamp = self.get_formatted_timestamp()
                
                # Decode received data (if possible)
                try:
                    decoded_data = data.decode('utf-8').strip()
                except UnicodeDecodeError:
                    decoded_data = f"<Binary data: {data.hex()[:100]}{'...' if len(data) > 50 else ''}>"
                
                # Log the received data
                print(f"[{timestamp}] Data received from {client_ip}:{client_port}: {decoded_data[:100]}")
                self.log_event(f"{client_ip}:{client_port}", 'DATA_RECEIVED', decoded_data)
                
                # Log to intrusion_log.txt
                self.log_intrusion(f"{client_ip}:{client_port}", f"Data received: {decoded_data[:50]}")
                
                # Log to JSON file
                self.log_intrusion_json(client_ip, timestamp, "Data Received")
                
                # Send a second warning
                try:
                    second_warning = "Your intrusion attempt has been recorded. Disconnect immediately.\r\n"
                    client_socket.sendall(second_warning.encode('utf-8'))
                    print(f"[{timestamp}] Second warning sent to {client_ip}:{client_port}")
                except Exception as e:
                    print(f"[{timestamp}] Failed to send second warning: {e}")
            
        except socket.timeout:
            timestamp = self.get_formatted_timestamp()
            print(f"[{timestamp}] Connection from {client_ip}:{client_port} timed out")
            self.log_event(f"{client_ip}:{client_port}", 'CONNECTION_TIMEOUT')
            self.log_intrusion(f"{client_ip}:{client_port}", "Connection timed out")
            self.log_intrusion_json(client_ip, timestamp, "Timeout")
            
        except socket.error as e:
            timestamp = self.get_formatted_timestamp()
            print(f"[{timestamp}] Socket error with {client_ip}:{client_port}: {e}")
            self.log_event(f"{client_ip}:{client_port}", 'SOCKET_ERROR', str(e))
            self.log_intrusion_json(client_ip, timestamp, "Socket Error")
            
        except Exception as e:
            timestamp = self.get_formatted_timestamp()
            print(f"[{timestamp}] Error handling client {client_ip}:{client_port}: {e}")
            self.log_event(f"{client_ip}:{client_port}", 'HANDLING_ERROR', str(e))
            self.log_intrusion_json(client_ip, timestamp, "Handling Error")
            traceback.print_exc()
            
        finally:
            # Clean up connection
            try:
                client_socket.close()
                if client_socket in self.connections:
                    self.connections.remove(client_socket)
            except:
                pass
            
            timestamp = self.get_formatted_timestamp()
            print(f"[{timestamp}] Connection with {client_ip}:{client_port} closed")
            self.log_event(f"{client_ip}:{client_port}", 'CONNECTION_CLOSED')
            self.log_intrusion(f"{client_ip}:{client_port}", "Connection closed")
            self.log_intrusion_json(client_ip, timestamp, "Connection Closed")
    
    def get_formatted_timestamp(self):
        """Return timestamp in the format YYYY-MM-DD HH:MM:SS"""
        return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    def log_event(self, source, action, data=None):
        """Log an event to the security log file"""
        timestamp = self.get_formatted_timestamp()
        
        log_entry = f"[{timestamp}] - {source} - {action}"
        if data:
            # Truncate data if it's too long
            if len(str(data)) > 1000:
                data_str = str(data)[:1000] + "... (truncated)"
            else:
                data_str = str(data)
            log_entry += f" - {data_str}"
        
        try:
            with open(self.security_log_file, 'a', encoding='utf-8') as f:
                f.write(log_entry + "\n")
        except Exception as e:
            timestamp = self.get_formatted_timestamp()
            print(f"[{timestamp}] Error writing to security log file: {e}")
            traceback.print_exc()
    
    def log_intrusion(self, ip, message):
        """Log an intrusion to the intrusion log file in the specified format"""
        timestamp = self.get_formatted_timestamp()
        
        # We're not using the correct format here
        # Current format is: [YYYY-MM-DD HH:MM:SS] Action from IP
        # But we want: [YYYY-MM-DD HH:MM:SS] Connection attempt from IP:PORT - Message
        
        # Don't create variable names with "log_entry"
        formatted_log = f"[{timestamp}] Connection attempt from {ip} - {message}"
        
        try:
            with open(self.intrusion_log_file, 'a', encoding='utf-8') as f:
                f.write(formatted_log + "\n")
        except Exception as e:
            timestamp = self.get_formatted_timestamp()
            print(f"[{timestamp}] Error writing to intrusion log file: {e}")
            traceback.print_exc()
    
    def log_intrusion_json(self, ip, timestamp, event):
        """Log an intrusion to the JSON log file
        
        Args:
            ip (str): The IP address of the intruder
            timestamp (str): The formatted timestamp of the event
            event (str): Description of the event (e.g., "Connection Attempt")
        """
        # Create the attack event object
        attack_event = {
            "ip": ip,
            "timestamp": timestamp,
            "event": event
        }
        
        try:
            # Read existing data
            existing_data = []
            if os.path.exists(self.intrusion_json_file) and os.path.getsize(self.intrusion_json_file) > 0:
                with open(self.intrusion_json_file, 'r') as f:
                    try:
                        existing_data = json.load(f)
                    except json.JSONDecodeError:
                        # If file is corrupted, start with empty list
                        existing_data = []
            
            # Append new event
            existing_data.append(attack_event)
            
            # Write back to file
            with open(self.intrusion_json_file, 'w') as f:
                json.dump(existing_data, f, indent=2)
                
        except Exception as e:
            timestamp = self.get_formatted_timestamp()
            print(f"[{timestamp}] Error writing to JSON log file: {e}")
            traceback.print_exc()

def signal_handler(sig, frame):
    """Handle interrupt signals gracefully"""
    print("\nStopping monitor...")
    if monitor:
        monitor.stop()
    sys.exit(0)

def main():
    """Main entry point"""
    # Setup signal handling
    signal.signal(signal.SIGINT, signal_handler)
    
    # Display welcome banner
    print("="*60)
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] HackfreeBank Intrusion Monitor v2.0")
    print(f"[{timestamp}] Monitors and logs unauthorized connection attempts")
    print("="*60)
    
    # Start the monitor
    global monitor
    monitor = IntrusionMonitor()
    monitor.start()

if __name__ == "__main__":
    monitor = None
    main() 