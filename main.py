from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os
import argparse


def generate_key(key_path="encryption.key"):
    key = get_random_bytes(16)  # 16 bytes for AES-128
    
    with open(key_path, "wb") as f:
        f.write(key)
        
    print(f"Key saved to {key_path}")
    return key

def load_key(key_path):
    if not os.path.exists(key_path):
        raise FileNotFoundError(f"Key file {key_path} not found.")
    with open(key_path, "rb") as f:
        return f.read()
    
def encrypt_file(file_path, key):
    """
    Encrypt a file using AES in CBC mode.
    """
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv

    with open(file_path, "rb") as f:
        plaintext = f.read()


    padding_length = AES.block_size - (len(plaintext) % AES.block_size)
    plaintext += bytes([padding_length]) * padding_length

    ciphertext = cipher.encrypt(plaintext)

    # Save the encrypted file
    encrypted_file_path = file_path + ".enc"
    with open(encrypted_file_path, "wb") as f:
        f.write(iv + ciphertext)

    print(f"File encrypted successfully: {encrypted_file_path}")


def decrypt_file(file_path, key):
    """
    Decrypt a file encrypted with AES in CBC mode.
    """
    with open(file_path, "rb") as f:
        iv = f.read(16)  # First 16 bytes are the IV
        ciphertext = f.read()

    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    plaintext = cipher.decrypt(ciphertext)


    padding_length = plaintext[-1]
    plaintext = plaintext[:-padding_length]


    decrypted_file_path = file_path.replace(".enc", "_decrypted")
    with open(decrypted_file_path, "wb") as f:
        f.write(plaintext)

    print(f"File decrypted successfully: {decrypted_file_path}")


def main():
    parser = argparse.ArgumentParser(
        description="File Encryption/Decryption Tool")
    parser.add_argument(
        "--generate-key", action="store_true", help="Generate a new encryption key"
    )
    parser.add_argument(
        "--key-path", type=str, default="encryption.key", help="Path to the key file"
    )
    parser.add_argument(
        "--encrypt", action="store_true", help="Encrypt the specified file"
    )
    parser.add_argument(
        "--decrypt", action="store_true", help="Decrypt the specified file"
    )
    parser.add_argument("--file", type=str,
                        help="Path to the file to encrypt/decrypt")

    args = parser.parse_args()

    if args.generate_key:
        generate_key(args.key_path)
    elif args.encrypt:
        if not args.file:
            print("Please specify a file to encrypt using --file.")
        else:
            key = load_key(args.key_path)
            encrypt_file(args.file, key)
    elif args.decrypt:
        if not args.file:
            print("Please specify a file to decrypt using --file.")
        else:
            key = load_key(args.key_path)
            decrypt_file(args.file, key)
    else:
        print("Please specify an operation: --generate-key, --encrypt, or --decrypt.")


if __name__ == "__main__":
    main()
    
    