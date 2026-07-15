# Encrypted Password Manager

A local command-line password manager that stores credentials in an encrypted SQLite vault. The master password is never stored on disk; it is used to derive an encryption key for the active session.

## Features

- Create and unlock a local encrypted password vault
- Add, view, edit, and delete saved credentials
- Change the master password and re-encrypt the vault
- Store encrypted vault data in SQLite
- Derive encryption keys with Argon2id
- Encrypt vault contents with AES-256-GCM authenticated encryption

## Security Design

The vault uses a zero-knowledge local design. The master password is not saved. Instead, it is combined with a randomly generated salt and passed through Argon2id to derive a 256-bit key.

Vault entries are serialized to JSON and encrypted with AES-GCM. Each save generates a new initialization vector, so repeated saves produce different ciphertext. AES-GCM also provides authentication, so tampering with encrypted data causes decryption to fail.

The local SQLite database stores:

```text
salt
iv
encrypted_data
created_at
updated_at
```

The plaintext vault only exists in memory after successful login.

## Requirements

- Python 3.10+
- `argon2-cffi`
- `cryptography`

Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Run the program:

```bash
python PasswordManager.py
```

On first launch, create a master password. On later launches, enter the same master password to decrypt the vault.

Menu options:

```text
1. View saved passwords
2. Add new password
3. Edit password
4. Delete password
5. Change master password
6. Exit
```

## Files

```text
PasswordManager.py      Main application
requirements.txt        Python dependencies
password_vault.db       Local encrypted vault database, created at runtime
```

`password_vault.db` is ignored by Git and should not be committed.

## Limitations

This is a personal security project and local prototype. It does not include cloud sync, browser integration, password generation, clipboard timeout handling, or formal security auditing.

## Project Details

Started: December 26, 2025  
Completed: December 27, 2025
