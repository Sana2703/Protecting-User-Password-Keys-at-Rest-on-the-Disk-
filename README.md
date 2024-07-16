# Protecting-User-Password-Keys-at-Rest-on-the-Disk-
This code primarily focuses on encryption and decryption of a file when the correct password is entered.

import os
import tkinter as tk
from tkinter import messagebox
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import re

class PasswordProtectedFileEncryption:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Protected File Encryption")

        self.file_label = tk.Label(root, text="File Path:")
        self.file_label.pack()

        self.file_entry = tk.Entry(root, width=50)
        self.file_entry.pack()

        self.browse_button = tk.Button(root, text="Browse", command=self.browse_file)
        self.browse_button.pack()

        self.password_label = tk.Label(root, text="Password:")
        self.password_label.pack()

        self.password_entry = tk.Entry(root, width=50, show="*")
        self.password_entry.pack()

        self.encrypt_button = tk.Button(root, text="Encrypt File", command=self.encrypt_file)
        self.encrypt_button.pack()

        self.decrypt_button = tk.Button(root, text="Decrypt File", command=self.decrypt_file)
        self.decrypt_button.pack()

    def browse_file(self):
        from tkinter import filedialog
        file_path = filedialog.askopenfilename()
        self.file_entry.delete(0, tk.END)
        self.file_entry.insert(0, file_path)

    def generate_key(self, password, salt):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        return key

    def encrypt_file(self):
        file_path = self.file_entry.get()
        password = self.password_entry.get()
        fixed_password = "Sahana@2003"  # Fixed password

        if password!= fixed_password:
            error_message = "Invalid password. "
            if len(password) < 8:
                error_message += "Password should be at least 8 characters long. "
            if not re.search("[a-z]", password):
                error_message += "Password should have at least one lowercase letter. "
            if not re.search("[A-Z]", password):
                error_message += "Password should have at least one uppercase letter. "
            if not re.search("[0-9]", password):
                error_message += "Password should have at least one digit. "
            if not re.search("[_@$]", password):
                error_message += "Password should have at least one special character. "
            messagebox.showerror("Error", error_message)
            return

        if not os.path.isfile(file_path):
            messagebox.showerror("Error", "File not found.")
            return

        salt = os.urandom(16)
        key = self.generate_key(password, salt)
        iv = os.urandom(16)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        with open(file_path, "rb") as file:
            data = file.read()

        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()

        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        encrypted_file_path = file_path + ".enc"
        with open(encrypted_file_path, "wb") as file:
            file.write(salt + iv + ciphertext)

        messagebox.showinfo("Success", "File encrypted successfully!")

    def decrypt_file(self):
        file_path = self.file_entry.get()
        password = self.password_entry.get()
        fixed_password = "Sahana@2003"  # Fixed password

        if password!= fixed_password:
            error_message = "Invalid password. "
            if len(password) < 8:
                error_message += "Password should be at least 8 characters long. "
            if not re.search("[a-z]", password):
                error_message += "Password should have at least one lowercase letter. "
            if not re.search("[A-Z]", password):
                error_message += "Password should have at least one uppercase letter. "
            if not re.search("[0-9]", password):
                error_message += "Password should have at least one digit. "
            if not re.search("[_@$]", password):
                error_message += "Password should have at least one special character. "
            messagebox.showerror("Error", error_message)
            return

        if not os.path.isfile(file_path):
            messagebox.showerror("Error", "File not found.")
            return

        with open(file_path, "rb") as file:
            salt = file.read(16)
            iv = file.read(16)
            ciphertext = file.read()

        key = self.generate_key(password, salt)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        padded_data = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()

        decrypted_file_path = file_path[:-4]
        with open(decrypted_file_path, "wb") as file:
            file.write(data)

        messagebox.showinfo("Success", "File decrypted successfully!")

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordProtectedFileEncryption(root)
    root.mainloop()
    
