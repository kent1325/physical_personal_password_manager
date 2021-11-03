import argparse
import constants
import pyperclip as pc
import pickle
from os import remove
from cryptography_helper import decrypt_password, decrypt_vault_file, encrypt_password

def load_args():
    """
    Loads the argument parser and adds the arguments needed.

    Returns:
        argument object: All of the added arguments are returned as objects.
    """
    my_parser = argparse.ArgumentParser(description="Password Manager Vault: Create and Delete Passwords for Emails", usage="[options]")

    my_parser.add_argument("-a", "--add", type=str, nargs=2, help="Add new entry", metavar=("[EMAIL]", "[PASSWORD]"))
    my_parser.add_argument("-l", "--list", action="store_true", help="List all entries from vault")
    my_parser.add_argument("-d", "--delete", type=str, nargs=1, help="Delete entry from vault", metavar=("[EMAIL]"))
    my_parser.add_argument("-c", "--copy_password", type=str, nargs=1, help="Copy password to clipboard", metavar=("[EMAIL]"))
    my_parser.add_argument("-u", "--update_password", type=str, nargs=2, help="Update a password for a specific email", metavar=("[EMAIL]", "[NEW_PASSWORD]"))

    return my_parser.parse_args()

def add_entry(args, vault):
    """Adds or updates an entry.

    Args:
        args (argparse): The arguments parsed.
        vault (dictionary): The vault with encrypted passwords.

    Returns:
        dictionary: The updated vault.
    """
    if args.add == None:
        email = args.update_password[0]
        password = args.update_password[1]
    else:
        email = args.add[0]
        password = args.add[1]
    vault[email] = encrypt_password(password)
    return vault

def delete_entry(args, vault):
    """Deletes an entry from the vault.

    Args:
        args (argparse): The arguments parsed.
        vault (dictionary): The vault with encrypted passwords.

    Returns:
        dictionary: The updated vault.
    """
    email = args.delete[0]
    del vault[email]
    return vault

def clipboard_password(args, vault):
    """Copying the password for a specific email to clipboard.

    Args:
        args (args): The argument parser.
        vault (dictionary): The vault with encrypted passwords.
    """
    email = args.copy_password[0]
    plaintext_password = decrypt_password(vault[email]).decode()
    pc.copy(plaintext_password)

def get_vault(_path=constants.VAULT_FILE):
    """Retrieving the current vault.

    Args:
        _path (file, optional): The path to the vault. Defaults to constants.VAULT_FILE.

    Returns:
        dictionary: The vault.
    """
    vault = {}
    decrypt_vault_file(_path, constants.MASTER_PASSWORD_HASHED)
    with open(_path, "rb") as vault_file:
        vault = pickle.load(vault_file)
    remove(_path)
    return vault
