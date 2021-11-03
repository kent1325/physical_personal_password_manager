import pyAesCrypt
import constants
from os import remove
from Crypto.Cipher import AES
from base64 import b64encode, b64decode

def encrypt_vault_file(vault_file, _master_password_hashed):
    """Encrypting the vault.

    Args:
        vault_file (file): Path to decrypted vault.
        _master_password_hashed (string): The master password hash.
    """
    pyAesCrypt.encryptFile(vault_file, constants.VAULT_ENC_FILE, _master_password_hashed)
    remove(vault_file)

def decrypt_vault_file(vault_file, _master_password_hashed):
    """Decrypting the vault.

    Args:
        vault_file (file): Path to decrypted vault.
        _master_password_hashed (string): The master password hash.
    """
    pyAesCrypt.decryptFile(constants.VAULT_ENC_FILE, vault_file, _master_password_hashed)

def encrypt_password(password_to_encrypt):
    """Encrypting plain text password to securely store later.

    Args:
        password_to_encrypt (string): plain text password
    """
    cipher = AES.new(constants.MASTER_PASSWORD_HASHED[-32:].encode(), AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext = cipher.encrypt(str.encode(password_to_encrypt))
    return b64encode(ciphertext + nonce).decode()

def decrypt_password(password_to_decrypt):
    """Decrypting encrypted password.

    Args:
        password_to_decrypt (string): An enrypted password.
    """
    password = b64decode(password_to_decrypt)
    cipher = AES.new(constants.MASTER_PASSWORD_HASHED[-32:].encode(), AES.MODE_EAX, password[-16:])
    return cipher.decrypt(password[:-16])
