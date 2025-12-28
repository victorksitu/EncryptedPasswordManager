import sqlite3
import os
import json
import getpass
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def create_connection(db_file='password_vault.db'):
    conn = sqlite3.connect('password_vault.db')
    return conn


def initialize_database(conn):
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS vault_data (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        salt BLOB NOT NULL,
        iv BLOB NOT NULL,
        encrypted_data BLOB NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
''')
    conn.commit()


def is_new_user(conn):
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM vault_data")
    count = cursor.fetchone()[0]
    return count == 0


def key_from_password(password: str, salt: bytes = None) -> dict:
    if salt is None:
        salt = os.urandom(16)
    if isinstance(password, str):
        password_bytes = password.encode('utf-8')
    
    key = hash_secret_raw(
        secret=password_bytes,
        salt=salt,
        time_cost=4,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        type=Type.ID
    )

    return {
        'key': key,
        'salt': salt
    }


def encrypt_data(data: dict, key: bytes) -> tuple:
    json_string = json.dumps(data)
    password_bytes = json_string.encode('utf-8')
    iv = os.urandom(12)
    cipher = AESGCM(key)

    encrypted_data = cipher.encrypt(iv, password_bytes, None)

    return (iv, encrypted_data)


def decrypt_data(encrypted_data: bytes, key: bytes, iv: bytes) -> dict:
    try:
        cipher = AESGCM(key)
        decrypted_bytes = cipher.decrypt(iv, encrypted_data, None)
    except Exception:
        raise ValueError("Decryption failed - wrong password")
    json_string = decrypted_bytes.decode('utf-8')
    data = json.loads(json_string)
    return data


def save_encrypted_vault(conn, salt: bytes, iv: bytes, encrypted_data: bytes):
    cursor = conn.cursor()
    if is_new_user(conn):
        cursor.execute(
            "INSERT INTO vault_data (salt, iv, encrypted_data) VALUES (?, ?, ?)",
            (salt, iv, encrypted_data)
        )
    else:
        cursor.execute(
            "UPDATE vault_data SET salt = ?, iv = ?, encrypted_data = ?, updated_at = CURRENT_TIMESTAMP WHERE id = 1",
            (salt, iv, encrypted_data)
        )
    conn.commit()


def load_encrypted_vault(conn):
    cursor = conn.cursor()
    cursor.execute("SELECT salt, iv, encrypted_data FROM vault_data LIMIT 1")
    row = cursor.fetchone()
    if row is None:
        return None
    return {
        'salt': row[0],
        'iv': row[1],
        'encrypted_data': row[2]
    }


def setup_new_user(conn):
    while True:
        password = getpass.getpass("Set Master Password:")
        confirm = getpass.getpass("Confirm Master Password:")

        if password!=confirm:
            print("Passwords do not match. Try again.")
            continue

        if len(password) < 8:
            print("Password should be at least 8 characters.")
            continue
        key_bundle = key_from_password(password)
        initial_vault = {"entries":[]}
        iv, encrypted_blob = encrypt_data(initial_vault, key_bundle['key'])
        save_encrypted_vault(conn, key_bundle['salt'], iv, encrypted_blob)
        print("Vault created and encrypted successfully.")
        return initial_vault, key_bundle['key'], key_bundle['salt']
    
def login_user(conn):
    stored = load_encrypted_vault(conn)
    if not stored:
        return None
    attempts = 3
    while attempts > 0:
        password = getpass.getpass("Enter Master Password:")
        key_bundle = key_from_password(password, salt=stored['salt'])

        try:
            decrypted_vault = decrypt_data(stored['encrypted_data'], key_bundle['key'], stored['iv'])
            return decrypted_vault, key_bundle['key'], stored['salt']
        except ValueError:
            attempts -= 1
            print("Invalid password. " + str(attempts) + " attempts remaining.")
    return None


def sync_vault_to_db(conn, vault_data, derived_key, salt):
    new_iv, encrypted_blob = encrypt_data(vault_data, derived_key)
    save_encrypted_vault(conn, salt, new_iv, encrypted_blob)


def display_passwords(vault_data):
    if not vault_data['entries']:
        print("\n[!] Vault is empty.")
        return
    print("\n" + "-"*75)
    for idx, entry in enumerate(vault_data['entries'], 1):
        print(f"[{idx}]{entry['service'].upper()}" + f"    User: {entry['username']}" + f"    Pass: {entry['password']}")
    print("-"*75)


def add_password_entry(conn, vault_data, derived_key, salt):
    print("\n" + "-"*75 + "\n")
    service = input("Service (Blank to cancel):")
    if not service:
        print("Operation cancelled.")
        return
    username = input("Username/Email:")
    password = input("Password:")
    vault_data['entries'].append({'service': service, 'username': username, 'password': password})
    sync_vault_to_db(conn, vault_data, derived_key, salt)
    print("Password added!")


def edit_password(conn, vault_data, derived_key, salt):
    display_passwords(vault_data)
    if not vault_data['entries']:
        return
    
    try:
        idx = int(input("\nSelect index to edit:")) - 1
        entry = vault_data['entries'][idx]
    except (ValueError, IndexError):
        print("Invalid Selection.")
        return
    
    while True:
        print("\n" + "-"*75)
        print(f"Editing: {entry['service'].upper()}".center(75))
        print("-"*75 + "\n")
        print(f"[1] Service:  {entry['service']}")
        print(f"[2] Username: {entry['username']}")
        print(f"[3] Password: {entry['password']}")
        print("[4] Finish & Save")
        print("[5] Cancel (Discard changes)")

        choice = input("What would you like to change?:")

        if choice == '1':
            entry['service'] = input(f"New Service [{entry['service']}]: ") or entry['service']
        elif choice == '2':
            entry['username'] = input(f"New Username [{entry['username']}]: ") or entry['username']
        elif choice == '3':
            entry['password'] = input(f"New Password [{entry['password']}]: ") or entry['password']
        elif choice == '4':
            sync_vault_to_db(conn, vault_data, derived_key, salt)
            print("Changes saved")
            break
        elif choice == '5':
            print("Edits cancelled. Reloading last saved state.")
            stored = load_encrypted_vault(conn)
            reloaded_vault = decrypt_data(stored['encrypted_data'], derived_key, stored['iv'])
            vault_data['entries'] = reloaded_vault['entries']
        else:
            print("Invalid choice.")


def delete_password(conn, vault_data, derived_key, salt):
    display_passwords(vault_data)
    if not vault_data['entries']:
        return
    try:
        idx = int(input("Select index to delete:")) - 1
        while True:
            confirm = input(f"Delete {vault_data['entries'][idx]['service']}? (y/n):")
            if confirm.lower() == 'y':
                vault_data['entries'].pop(idx)
                sync_vault_to_db(conn, vault_data, derived_key, salt)
                print("Deleted.")
                return
            elif confirm.lower() == 'n':
                return
            else:
                print("Invalid selection.")
                continue
    except (ValueError, IndexError): 
        print("Invalid selection.")


def change_master_password(conn, vault_data, old_key, old_salt):
    print("\n" + "-"*75 + "\n")
    new_pwd = getpass.getpass("Enter New Master Password (Blank to quit): ")
    if not new_pwd:
        print("Operation aborted. Master password unchanged.")
        return old_key, old_salt
    
    if len(new_pwd) < 8:
        print("Error: New password must be at least 8 characters long.")
        return old_key, old_salt
    
    confirm = getpass.getpass("Confirm New Master Password: ")
    if new_pwd != confirm:
        print("Error: Passwords do not match. Aborting.")
        return old_key, old_salt
    new_bundle = key_from_password(new_pwd)
    sync_vault_to_db(conn, vault_data, new_bundle['key'], new_bundle['salt'])
    print("Master Password Updated.")
    return new_bundle['key'], new_bundle['salt']


def run_vault_menu(conn, vault_data, derived_key, salt):
    while True:
        print("\n"+"-"*75)
        print("|" + "Vault Menu".center(73) + "|")
        print("-"*75+"\n")
        print("[1] View Saved Passwords")
        print("[2] Add New Password")
        print("[3] Edit Password")
        print("[4] Delete Password")
        print("[5] Change Master Password")
        print("[6] Exit")

        choice = input("\nSelection:")
        if choice == '1':
            display_passwords(vault_data)
        elif choice == '2':
            add_password_entry(conn, vault_data, derived_key, salt)
        elif choice == '3':
            edit_password(conn, vault_data, derived_key, salt)
        elif choice == '4':
            delete_password(conn, vault_data, derived_key, salt)
        elif choice == '5':
            derived_key, salt = change_master_password(conn, vault_data, derived_key, salt)
        elif choice == '6':
            print("Goodbye!")
            break


def main():
    conn = create_connection()
    initialize_database(conn)
    print("-"*75)
    print("|" + "Secure Password Vault".center(73) + "|")
    print("-"*75)

    result = None
    if is_new_user(conn):
        print("\nWelcome to your Password Vault! Lets setup your Master Password.")
        result = setup_new_user(conn)
    else:
        print("\nWelcome back to your Password Vault!")
        result = login_user(conn)
    if result is not None:
        print("\nAccess Granted. Your vault is unlocked.")
        run_vault_menu(conn, *result)

    else:
        print("\nAccess Denied. Exiting.")
    conn.close()


main()
