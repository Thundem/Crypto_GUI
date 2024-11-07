# Crypto GUI Application

## Description

Crypto GUI is a Python-based graphical application that allows users to encrypt and decrypt messages using various cryptographic algorithms (AES, RSA, and Fernet). It also provides functionality to send encrypted messages via email. The application features a user-friendly interface built with `tkinter`.

## Features

- **Encryption Algorithms**: Supports AES, RSA, and Fernet encryption methods.
- **GUI Interface**: Easy-to-use graphical interface for encrypting, decrypting, and sending messages.
- **Email Integration**: Ability to send encrypted messages via email.
- **Placeholder Inputs**: User-friendly input fields with placeholders.
- **Customizable UI**: Simple customization of interface colors and layouts.

## Requirements

- **Python 3.6+**
- **pip package manager**

### Python Libraries

- `cryptography`
- `tkinter` (usually comes with Python)
- `pyopenssl`

## Installation

1. **Clone the repository** (or download the code):

   ```bash
   git clone https://github.com/yourusername/crypto-gui.git
   cd crypto-gui
   ```

2. **Create a virtual environment** (optional but recommended):

   ```bash
   python -m venv venv
   ```

3. **Activate the virtual environment**:

   On Windows:

   ```bash
   venv\Scripts\activate
   ```

   On Linux/MacOS:

   ```bash
   source venv/bin/activate
   ```

4. **Install the required packages**:

   ```bash
   pip install -r requirements.txt
   ```

   Or install them individually:

   ```bash
   pip install cryptography pyopenssl
   ```

## Configuration

### Email Setup

To enable the email sending functionality, you need to configure your email credentials.

1. **Set up an App Password** (for Gmail users):

   - Enable Two-Factor Authentication on your Google account.
   - Generate an App Password in your Google account settings.
   - Note down the 16-character app password.

2. **Set the environment variable**:

   On Windows:

   ```cmd
   set CRYPTO_GUI_PASSWORD=your_app_password
   ```

   On Linux/MacOS:

   ```bash
   export CRYPTO_GUI_PASSWORD=your_app_password
   ```

3. **Replace the sender email in the code**:

   In the `send_email` function within `crypto_gui.py`, replace `"vovkandrij7@gmail.com"` with your email address.

   ```python
   sender_email = "your_email@gmail.com"
   ```

   Optional: To avoid modifying the code, you can further refactor the code to read the sender email from an environment variable as well.

### SMTP Server Configuration (if not using Gmail)

If you're using a different email provider, update the SMTP server settings in the `send_email` function.

```python
with smtplib.SMTP_SSL('smtp.yourprovider.com', port_number) as server:
```

## Usage

1. **Run the application**:

   ```bash
   python crypto_gui.py
   ```

2. **Encrypt a message**:

   - Enter your message in the "Enter your message" field.
   - Select the encryption algorithm (AES, RSA, Fernet).
   - Click the "Encrypt" button.
   - Choose a location to save the encrypted file.

3. **Decrypt a message**:

   - Select the encryption algorithm used to encrypt the message.
   - Click the "Decrypt" button.
   - Choose the encrypted file to decrypt.
   - The decrypted message will be displayed in a popup.

4. **Send an encrypted message via email**:

   - Enter the recipient's email address in the placeholder field.
   - Click the "Send Message" button.
   - Select the encrypted file you wish to send.
   - The application will send the email to the recipient.

## Notes

- **Key Persistence**: The application generates new keys each time it runs. If you need persistent keys, modify the code to save and load keys from files.
- **Security**: Never share your email password or app password. Use environment variables to store sensitive information.
- **Dependencies**: Ensure all required Python packages are installed in your environment.
