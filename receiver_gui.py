import os
import tkinter as tk
from tkinter import filedialog, messagebox
import base64

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization

# Функції завантаження ключів

# AES
def load_aes_key(filename):
    with open(filename, 'rb') as f:
        key = f.read()
    return key

# RSA
def load_rsa_private_key(filename):
    with open(filename, 'rb') as f:
        pem_data = f.read()
    private_key = serialization.load_pem_private_key(
        pem_data,
        password=None,
        backend=default_backend()
    )
    return private_key

# Fernet
def load_fernet_key(filename):
    with open(filename, 'rb') as f:
        key = f.read()
    return key

# Функції розшифровки

def decrypt_aes(ciphertext, key):
    iv = ciphertext[:16]
    actual_ciphertext = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(actual_ciphertext) + decryptor.finalize()
    return decrypted_message.decode('utf-8')

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

def decrypt_fernet(token, key):
    f = Fernet(key)
    decrypted_message = f.decrypt(token)
    return decrypted_message.decode('utf-8')

# Головна функція для створення GUI

def create_receiver_gui():
    def decrypt_message():
        algorithm = algorithm_var.get()

        # Вибір файлу з зашифрованим повідомленням
        open_path = filedialog.askopenfilename(title="Виберіть зашифроване повідомлення", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if not open_path:
            messagebox.showwarning("Попередження", "Файл повідомлення не було вибрано")
            return

        # Вибір ключа
        key_path = filedialog.askopenfilename(title="Виберіть файл ключа", filetypes=[("Key Files", "*.key;*.pem"), ("All Files", "*.*")])
        if not key_path:
            messagebox.showwarning("Попередження", "Файл ключа не було вибрано")
            return

        try:
            # Читання зашифрованого повідомлення
            with open(open_path, 'rb') as f:
                encrypted_data = f.read()

            # Якщо повідомлення було збережене в Base64 (опціонально)
            try:
                encrypted_data = base64.b64decode(encrypted_data)
            except:
                pass  # Якщо не Base64, продовжуємо зчитувати як бінарні дані

            if algorithm == "AES":
                key = load_aes_key(key_path)
                decrypted = decrypt_aes(encrypted_data, key)
            elif algorithm == "RSA":
                private_key = load_rsa_private_key(key_path)
                decrypted = decrypt_rsa(encrypted_data, private_key)
            elif algorithm == "Fernet":
                key = load_fernet_key(key_path)
                decrypted = decrypt_fernet(encrypted_data, key)
            else:
                messagebox.showerror("Помилка", "Оберіть алгоритм розшифрування")
                return

            # Відображення розшифрованого повідомлення
            messagebox.showinfo("Розшифроване повідомлення", decrypted)

        except Exception as e:
            messagebox.showerror("Помилка", f"Не вдалося розшифрувати повідомлення: {e}")

    app = tk.Tk()
    app.title("Дешифратор повідомлень")
    app.configure(bg="#82a5c5")

    # Вибір алгоритму шифрування
    algorithm_var = tk.StringVar(value="AES")
    algorithms = [("AES", "AES"), ("RSA", "RSA"), ("Fernet", "Fernet")]

    algorithm_frame = tk.Frame(app, bg="#82a5c5")
    algorithm_frame.pack(pady=10)

    algorithm_label = tk.Label(algorithm_frame, text="Оберіть алгоритм шифрування:", bg="#82a5c5")
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

    # Кнопка для розшифровки
    decrypt_button = tk.Button(app, text="Розшифрувати повідомлення", command=decrypt_message, width=25)
    decrypt_button.pack(pady=20)

    app.mainloop()

if __name__ == "__main__":
    create_receiver_gui()