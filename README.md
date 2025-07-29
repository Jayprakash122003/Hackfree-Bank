# HackFreeBank - Secure Banking Application

A secure banking web application built with Python and Flask that implements modern security features including two-factor authentication, secure password storage, session management, and brute force protection.

## Features

- **User Authentication**
  - Secure login and registration
  - Password hashing with bcrypt
  - Two-factor authentication (TOTP)

- **Banking Operations**
  - View account balance
  - Make deposits
  - Make withdrawals
  - Transaction history with timestamps

- **Security Features**
  - IP-based brute force protection
  - Session management
  - Security logging
  - Password complexity requirements

- **Dual Interface**
  - Web interface with Bootstrap
  - Command-line interface (CLI)

## Project Structure

```
/HackFreeBank
│
├── app.py              # Main Flask application
├── cli.py              # Command-line interface
├── models.py           # Database models
├── forms.py            # WTForms form definitions
├── requirements.txt    # Project dependencies
│
├── /templates          # HTML templates
│   ├── base.html
│   ├── index.html
│   ├── dashboard.html
│   └── ...
│
├── /static             # Static files
│   ├── /css
│   │   └── style.css
│   └── /js
│       └── script.js
│
├── /utils              # Utility modules
│   ├── logger.py
│   ├── security.py
│   └── two_factor.py
│
└── /logs               # Log files
    └── security.log
```

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/hackfreebank.git
   cd hackfreebank
   ```

2. Create and activate a virtual environment:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

4. Create a `.env` file in the project root with your configuration:
   ```
   SECRET_KEY=YourSuperSecretKey
   DATABASE_URI=sqlite:///database.db
   MAIL_SERVER=smtp.gmail.com
   MAIL_PORT=587
   MAIL_USE_TLS=True
   MAIL_USERNAME=your-email@gmail.com
   MAIL_PASSWORD=your-app-password
   MAIL_DEFAULT_SENDER=your-email@gmail.com
   DEBUG=True
   ```

5. Initialize the database:
   ```
   python
   >>> from app import app, db
   >>> with app.app_context():
   ...     db.create_all()
   >>> exit()
   ```

## Usage

### Web Interface

Run the Flask application:
```
python app.py
```

Access the application at http://localhost:5000

### Command Line Interface

The application can also be used via command line:

```
# Create a new account
python cli.py register --username john --email john@example.com

# Check account balance
python cli.py balance --username john

# Make a deposit
python cli.py deposit --username john --amount 100.00 --description "Initial deposit"

# Make a withdrawal
python cli.py withdraw --username john --amount 50.00 --description "Grocery shopping"

# View transaction history
python cli.py history --username john --limit 10
```

## Security Notes

- For production use, make sure to:
  - Use a proper web server (Gunicorn, uWSGI, etc.) with a reverse proxy
  - Set DEBUG=False in your .env file
  - Use a strong, randomly generated SECRET_KEY
  - Configure proper email settings for two-factor authentication
  - Consider using HTTPS with a valid SSL certificate

## License

This project is licensed under the MIT License - see the LICENSE file for details.

# HackFreeBank Cybersecurity Layer

This directory contains tools that provide a basic cybersecurity layer for HackFreeBank, simulating intrusion detection and data encryption.

## Files and Structure

```
.
├── monitor.py                  # Intrusion detection script
├── intrusion_log.txt           # Auto-generated log of intrusion attempts
├── encryption_key.key          # Auto-generated encryption key
├── utils/
│   └── encryptor.py            # Data encryption/decryption utility
└── dataset/
    ├── original_data.json      # Original sensitive data
    └── encrypted_data.json     # Encrypted version of the data
```

## Usage

### Intrusion Monitor

The intrusion monitor listens for unauthorized connections on port 9999, logs them, and sends warning messages to potential attackers.

To start the intrusion monitor:

```bash
python monitor.py
```

This will:
- Listen on port 9999 for incoming connections
- Log all connection attempts to `intrusion_log.txt`
- Send warning messages to any connected clients

### Data Encryption Utility

The encryption utility uses a simple XOR-based encryption method with Base64 encoding to encrypt and decrypt sensitive data. This is for demonstration purposes only and is not secure for production use.

To use the encryption utility:

```bash
python -c "from utils.encryptor import Encryptor; Encryptor().encrypt_data()"
```

To decrypt and view the data:

```bash
python -c "from utils.encryptor import Encryptor; print(Encryptor().decrypt_data())"
```

You can also run the encryptor script directly:

```bash
python utils/encryptor.py
```

This will:
- Generate an encryption key if one doesn't exist
- Encrypt the data in `dataset/original_data.json`
- Save the encrypted data to `dataset/encrypted_data.json`
- Decrypt and display the data

## Requirements

- Python 3.6+

Install required packages:

```bash
pip install cryptography
```

## Testing the Intrusion Monitor

To test the intrusion monitor, you can use tools like telnet or netcat:

```bash
# Using telnet
telnet localhost 9999

# Or using netcat
nc localhost 9999
```

Type any message and press Enter. The monitor will:
1. Detect the connection
2. Log the attempt in `intrusion_log.txt`
3. Send a warning message back
4. Close the connection

## Security Notes

- This is a simulation for educational purposes only
- The encryption key is stored locally, which is not secure for production
- For a real system, proper key management and secure storage would be required
- The intrusion monitor is basic and only detects connections, not sophisticated attacks 