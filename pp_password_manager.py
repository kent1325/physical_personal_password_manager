from argon2 import PasswordHasher
import getpass
import sys
from os import path
import argument_helper
import cryptography_helper
import constants
import pickle
import pprint

def save_vault(vault=None):
    """Decrypts the encrypted vault and overwrites it.

    Args:
        vault (dictionary, optional): The vault with the newly added changes. Defaults to None.
    """
    try:
        cryptography_helper.decrypt_vault_file(constants.VAULT_FILE, constants.MASTER_PASSWORD_HASHED)
        with open(constants.VAULT_FILE, "wb") as vault_file:
            pickle.dump(vault, vault_file)
    except Exception as e:
        print(e)
    finally:
        cryptography_helper.encrypt_vault_file(constants.VAULT_FILE, constants.MASTER_PASSWORD_HASHED)

def initialise_vault():
    """
    Initiates the vault with an empty file and encrypts it.
    """
    if not path.isfile(constants.VAULT_ENC_FILE) and not path.isfile(constants.VAULT_FILE):
        try:
            with open(constants.VAULT_FILE, "wb") as vault_file:
                pickle.dump({}, vault_file)
            cryptography_helper.encrypt_vault_file(constants.VAULT_FILE, constants.MASTER_PASSWORD_HASHED)
        except Exception as e:
            print(e)
            sys.exit()
    return


if __name__ == '__main__':
    """
    The main code, which handles the usage of the vault.
    """
    master_password_input = getpass.getpass("Enter the Master Password: ")

    ph = PasswordHasher(time_cost=50, hash_len=32, salt_len=32, memory_cost=256000)
    try:
        ph.verify(constants.MASTER_PASSWORD_HASHED, master_password_input)
    except Exception as e:
        print(e)
        sys.exit()

    initialise_vault()

    pp = pprint.PrettyPrinter()
    args = argument_helper.load_args()
    args_dict = {key:val for key, val in vars(args).items() if val != None and val != False}
    keys = list(args_dict.keys())[0]
    values = list(args_dict.values())[0]
    vault = argument_helper.get_vault()

    match keys:
        case "add":
            if values[0] in vault.keys():
                print("Email already exists.")
                sys.exit()
            updated_vault = argument_helper.add_entry(args, vault)
            save_vault(updated_vault)
            print("*** Entity successfully added ***")
        case "list":
            print("************* VAULT *************")
            pp.pprint(vault)
            print("*********************************")
        case "delete":
            if not values[0] in vault.keys():
                print("Email does not exist.")
                sys.exit()
            updated_vault = argument_helper.delete_entry(args, vault)
            save_vault(updated_vault)
            print("*** Entity successfully deleted ***")
        case "copy_password":
            if not values[0] in vault.keys():
                print("Email does not exist.")
                sys.exit()
            argument_helper.clipboard_password(args, vault)
            print("*** Password successfully copied to clipboard ***")
        case "update_password":
            if not values[0] in vault.keys():
                print("Email does not exist.")
                sys.exit()
            updated_vault = argument_helper.add_entry(args, vault)
            save_vault(updated_vault)
            print("*** Entity successfully updated ***")
