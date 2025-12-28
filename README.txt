To use this tool, first install the requirements via:
pip3 install -r requirements.txt

Next open cmd in the directory and type python PasswordManager.py

This is an encrypted password manager project that stores passwords locally and
uses a master password to encrypt / decrypt.
Designed with a Zero-Knowledge architecture, meaning that your master password is never stored on disk,
and your data is only decrypted in your computer's memory during an active session.

Uses industry-standard cryptographic primitives to ensure data is unreadable even if database file is stolen.
- Argon2id Key Derivation: Transforms master password into a 256-bit encryption key using a unique 16-byte salt.
- AES-GCM Encryption: Provides both high-speed encryption and data integrity, ensuring your vault hasn't been tampered with.
- Unique Initialization Vectors: Every save or edit of an entry generates a new IV, ensuring if you save the same
password twice, the resulting output is completely different.


NOTE: When typing master password, text will not appear but it is being written.

Start date: December 26, 2025
End date: December 27, 2025