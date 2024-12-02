# Advance file encryption and decryption tool
A Python-based command-line tool for encrypting and decrypting files.


## Usage

### Command-Line Interface
```bash
# Generate key
python main.py --generate-key

# encrypt a file based on the generated key
python main.py --encrypt --file <path_to_file> --key-path encryption.key

# decrypt the encrypted a file based on the generated key
python main.py --decrypt --file <path_to_encrypted_file> --key-path encryption.key
```
