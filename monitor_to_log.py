import os
import subprocess
import time
import signal
import sys

def ensure_log_directory():
    """Ensure the logs directory exists"""
    logs_dir = os.path.join(os.path.dirname(__file__), 'logs')
    if not os.path.exists(logs_dir):
        os.makedirs(logs_dir)
    return logs_dir

def run_monitor_and_log():
    """Run the monitor.py script and save its output to a log file"""
    logs_dir = ensure_log_directory()
    log_file_path = os.path.join(logs_dir, 'monitor_log.txt')
    
    print(f"Starting monitor.py and logging output to {log_file_path}")
    
    # Start the monitor.py process
    with open(log_file_path, 'a', encoding='utf-8') as log_file:
        # Add a header to the log file
        log_file.write("\n\n" + "="*60 + "\n")
        log_file.write(f"MONITOR SESSION STARTED: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        log_file.write("="*60 + "\n\n")
        log_file.flush()
        
        monitor_process = subprocess.Popen(
            ['python', 'monitor.py'],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1  # Line buffered
        )
        
        try:
            # Read the output and write to the log file
            for line in monitor_process.stdout:
                print(line.strip())  # Print to console
                log_file.write(line)  # Write to log file
                log_file.flush()  # Ensure it's written immediately
                
        except KeyboardInterrupt:
            print("\nStopping monitor...")
            log_file.write("\n\n" + "="*60 + "\n")
            log_file.write(f"MONITOR SESSION ENDED: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            log_file.write("="*60 + "\n\n")
            monitor_process.terminate()
            monitor_process.wait(timeout=5)
            print("Monitor stopped.")
            sys.exit(0)

def signal_handler(sig, frame):
    print("\nStopping monitor...")
    sys.exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    run_monitor_and_log() 