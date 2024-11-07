import os
import datetime
import tkinter as tk
from tkinter import filedialog, messagebox
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization

def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def create_self_signed_cert(private_key, public_key):
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"UA"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Lviv"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Lviv"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Thundem"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"thundem.com"),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        public_key
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).sign(private_key, hashes.SHA256(), default_backend())
    return cert

# AES
def save_aes_key(key, filename):
    with open(filename, 'wb') as f:
        f.write(key)

def load_aes_key(filename):
    with open(filename, 'rb') as f:
        key = f.read()
    return key

# RSA
def save_rsa_private_key(private_key, filename):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()  # Можна додати парольний захист
    )
    with open(filename, 'wb') as f:
        f.write(pem)

def load_rsa_private_key(filename):
    with open(filename, 'rb') as f:
        pem_data = f.read()
    private_key = serialization.load_pem_private_key(
        pem_data,
        password=None,  # Якщо додасте парольний захист, змініть це
        backend=default_backend()
    )
    return private_key

def save_rsa_public_key(public_key, filename):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(filename, 'wb') as f:
        f.write(pem)

def load_rsa_public_key(filename):
    with open(filename, 'rb') as f:
        pem_data = f.read()
    public_key = serialization.load_pem_public_key(
        pem_data,
        backend=default_backend()
    )
    return public_key

# Fernet
def save_fernet_key(key, filename):
    with open(filename, 'wb') as f:
        f.write(key)

def load_fernet_key(filename):
    with open(filename, 'rb') as f:
        key = f.read()
    return key

# Функції шифрування та розшифровки

def encrypt_aes(message, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_message = message.encode('utf-8')
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()
    return iv + ciphertext

def decrypt_aes(ciphertext, key):
    iv = ciphertext[:16]
    actual_ciphertext = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(actual_ciphertext) + decryptor.finalize()
    return decrypted_message.decode('utf-8')

def encrypt_rsa(message, public_key):
    ciphertext = public_key.encrypt(
        message.encode('utf-8'),
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def decrypt_rsa(ciphertext, private_key):
    decrypted_message = private_key.decrypt(
        ciphertext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_message.decode('utf-8')

def encrypt_fernet(message, key):
    f = Fernet(key)
    token = f.encrypt(message.encode('utf-8'))
    return token

def decrypt_fernet(token, key):
    f = Fernet(key)
    decrypted_message = f.decrypt(token)
    return decrypted_message.decode('utf-8')

def send_email(file_path, recipient_email):
    sender_email = "vovkandrij7@gmail.com"  # Замініть на вашу електронну адресу
    password = os.getenv('CRYPTO_GUI_PASSWORD')

    msg = MIMEMultipart()
    msg['Subject'] = 'Зашифроване повідомлення'
    msg['From'] = sender_email
    msg['To'] = recipient_email

    # Текст листа
    body = "Дивіться вкладений файл із зашифрованим повідомленням."
    msg.attach(MIMEText(body, 'plain'))

    # Прикріплення файлу
    try:
        with open(file_path, 'rb') as attachment:
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(attachment.read())

        encoders.encode_base64(part)
        part.add_header(
            'Content-Disposition',
            f'attachment; filename="{os.path.basename(file_path)}"'
        )
        msg.attach(part)
    except Exception as e:
        messagebox.showerror("Помилка", f"Не вдалося прикріпити файл: {e}")
        return

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(sender_email, password)
            server.send_message(msg)
        messagebox.showinfo("Успіх", "Лист успішно відправлено")
    except Exception as e:
        messagebox.showerror("Помилка", f"Не вдалося відправити лист: {e}")

def create_gui():
    def encrypt_message():
        message = message_entry.get()
        algorithm = algorithm_var.get()

        if not message:
            messagebox.showwarning("Попередження", "Введіть повідомлення для шифрування")
            return

        if algorithm == "AES":
            # Генеруємо новий AES ключ
            symmetric_key = os.urandom(32)
            # Зберігаємо ключ у файл
            key_save_path = 'aes_key.key'
            if not key_save_path:
                messagebox.showwarning("Попередження", "Ключ не було збережено")
                return
            save_aes_key(symmetric_key, key_save_path)
            encrypted = encrypt_aes(message, symmetric_key)
        elif algorithm == "RSA":
            # Генеруємо нову пару ключів RSA
            private_key, public_key = generate_rsa_keys()
            cert = create_self_signed_cert(private_key, public_key)
            # Зберігаємо приватний та публічний ключі у файли
            private_key_save_path = 'rsa_private_key.pem'
            if not private_key_save_path:
                messagebox.showwarning("Попередження", "Приватний ключ не було збережено")
                return
            save_rsa_private_key(private_key, private_key_save_path)

            public_key_save_path = 'rsa_public_key.pem'
            if not public_key_save_path:
                messagebox.showwarning("Попередження", "Публічний ключ не було збережено")
                return
            save_rsa_public_key(public_key, public_key_save_path)

            encrypted = encrypt_rsa(message, public_key)
        elif algorithm == "Fernet":
            # Генеруємо новий Fernet ключ
            fernet_key = Fernet.generate_key()
            # Зберігаємо ключ у файл
            key_save_path = 'fernet_key.key'
            if not key_save_path:
                messagebox.showwarning("Попередження", "Ключ не було збережено")
                return
            save_fernet_key(fernet_key, key_save_path)
            encrypted = encrypt_fernet(message, fernet_key)
        else:
            messagebox.showerror("Помилка", "Оберіть алгоритм шифрування")
            return

        # Збереження зашифрованого повідомлення у файл
        save_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text  files", "*.txt"), ("All files", "*.*")])
        if save_path:
            try:
                with open(save_path, 'wb') as f:
                    f.write(encrypted)
                messagebox.showinfo("Успіх", f"Зашифроване повідомлення збережено у файл:\n{save_path}")
            except Exception as e:
                messagebox.showerror("Помилка", f"Не вдалося зберегти файл: {e}")
        else:
            messagebox.showwarning("Попередження", "Файл не було збережено")

    def decrypt_message():
        algorithm = algorithm_var.get()

        # Вибір файлу з зашифрованим повідомленням
        open_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if not open_path:
            messagebox.showwarning("Попередження", "Файл не було вибрано")
            return

        try:
            with open(open_path, 'rb') as f:
                encrypted = f.read()

            if algorithm == "AES":
                # Вибираємо AES ключ
                key_path = filedialog.askopenfilename(title="Виберіть AES ключ", filetypes=[("Key Files", "*.key"), ("All Files", "*.*")])
                if not key_path:
                    messagebox.showwarning("Попередження", "Ключ не було вибрано")
                    return
                symmetric_key = load_aes_key(key_path)
                decrypted = decrypt_aes(encrypted, symmetric_key)
            elif algorithm == "RSA":
                # Вибираємо RSA приватний ключ
                key_path = filedialog.askopenfilename(title="Виберіть RSA приватний ключ", filetypes=[("PEM Files", "*.pem"), ("All Files", "*.*")])
                if not key_path:
                    messagebox.showwarning("Попередження", "Ключ не було вибрано")
                    return
                private_key = load_rsa_private_key(key_path)
                decrypted = decrypt_rsa(encrypted, private_key)
            elif algorithm == "Fernet":
                # Вибираємо Fernet ключ
                key_path = filedialog.askopenfilename(title="Виберіть Fernet ключ", filetypes=[("Key Files", "*.key"), ("All Files", "*.*")])
                if not key_path:
                    messagebox.showwarning("Попередження", "Ключ не було вибрано")
                    return
                fernet_key = load_fernet_key(key_path)
                decrypted = decrypt_fernet(encrypted, fernet_key)
            else:
                messagebox.showerror("Помилка", "Оберіть алгоритм розшифровки")
                return

            messagebox.showinfo("Результат", f"Розшифроване повідомлення:\n{decrypted}")
        except Exception as e:
            messagebox.showerror("Помилка", f"Не вдалося розшифрувати повідомлення: {e}")

    def send_encrypted_email():
        recipient = recipient_entry.get()
        if not recipient or recipient == 'Електронна адреса отримувача':
            messagebox.showwarning("Попередження", "Введіть електронну адресу отримувача")
            return

        open_path = filedialog.askopenfilename(title="Виберіть файл із зашифрованим повідомленням", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if not open_path:
            messagebox.showwarning("Попередження", "Файл не було вибрано")
            return

        try:
            send_email(open_path, recipient)
        except Exception as e:
            messagebox.showerror("Помилка", f"Не вдалося відправити лист: {e}")

    app = tk.Tk()
    app.title("Crypto GUI")
    app.configure(bg="#82a5c5")

    message_frame = tk.Frame(app, bg="#82a5c5")
    message_frame.pack(pady=10)

    message_label = tk.Label(message_frame, text="Введіть повідомлення:", bg="#82a5c5")
    message_label.grid(row=0, column=0, padx=5)

    message_entry = tk.Entry(message_frame, width=30)
    message_entry.grid(row=0, column=1, padx=5)

    # Вибір алгоритму шифрування
    algorithm_var = tk.StringVar(value="AES")
    algorithms = [("AES", "AES"), ("RSA", "RSA"), ("Fernet", "Fernet")]

    algorithm_frame = tk.Frame(app, bg="#82a5c5")
    algorithm_frame.pack(pady=10)

    algorithm_label = tk.Label(algorithm_frame, text="Оберіть алгоритм:", bg="#82a5c5")
    algorithm_label.grid(row=0, column=0, padx=5)

    for idx, (text, mode) in enumerate(algorithms):
        algorithm_radio = tk.Radiobutton(
            algorithm_frame,
            text=text,
            variable=algorithm_var,
            value=mode,
            bg="#82a5c5"
        )
        algorithm_radio.grid(row=0, column=idx + 1, padx=5)

    buttons_frame = tk.Frame(app, bg="#82a5c5")
    buttons_frame.pack(pady=10)

    button_width = 15

    encrypt_button = tk.Button(buttons_frame, text="Зашифрувати", command=encrypt_message, width=button_width)
    encrypt_button.grid(row=0, column=0, padx=5)

    decrypt_button = tk.Button(buttons_frame, text="Розшифрувати", command=decrypt_message, width=button_width)
    decrypt_button.grid(row=0, column=1, padx=5)

    email_frame = tk.Frame(app, bg="#82a5c5")
    email_frame.pack(pady=10)

    def on_entry_click(event):
        if recipient_entry.get() == 'Електронна адреса отримувача':
            recipient_entry.delete(0, "end")
            recipient_entry.config(fg='black')

    def on_focusout(event):
        if recipient_entry.get() == '':
            recipient_entry.insert(0, 'Електронна адреса отримувача')
            recipient_entry.config(fg='grey')

    recipient_entry = tk.Entry(email_frame, width=40)
    recipient_entry.grid(row=0, column=0, padx=5)
    recipient_entry.insert(0, 'Електронна адреса отримувача')
    recipient_entry.config(fg='grey')

    recipient_entry.bind('<FocusIn>', on_entry_click)
    recipient_entry.bind('<FocusOut>', on_focusout)

    send_button = tk.Button(email_frame, text="Надіслати повідомлення", command=send_encrypted_email)
    send_button.grid(row=0, column=1, padx=5)

    app.mainloop()

if __name__ == "__main__":
    create_gui()