from charm.toolbox.pairinggroup import PairingGroup
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
import time
import os

def create_policy(num_attributes):
    return ' or '.join(['attribute{}'.format(i + 1) for i in range(num_attributes)])

def process_file(cpabe, public_key, master_key, file_path, attributes, num_attributes):
    try:
        with open(file_path, 'rb') as f:
            start_time = time.time()
            file_content = f.read()
            file_read_time = time.time() - start_time
        file_size = os.path.getsize(file_path)
    except FileNotFoundError:
        print(f"File {file_path} not found.")
        return None
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return None

    policy = create_policy(num_attributes)

    # Key generation
    start_time = time.time()
    secret_key = cpabe.keygen(public_key, master_key, attributes)
    keygen_time = time.time() - start_time

    # Encryption
    start_time = time.time()
    ciphertext = cpabe.encrypt(public_key, file_content, policy)
    encryption_time = time.time() - start_time

    # Decryption
    start_time = time.time()
    decrypted_content = cpabe.decrypt(public_key, secret_key, ciphertext)
    decryption_time = time.time() - start_time

    # Re-Key generation for updated policy (one fewer attribute)
    updated_policy = create_policy(num_attributes - 1)
    start_time = time.time()
    updated_secret_key = cpabe.keygen(public_key, master_key, attributes[:num_attributes - 1])
    rekeygen_time = time.time() - start_time

    # Re-Encryption
    start_time = time.time()
    updated_ciphertext = cpabe.encrypt(public_key, file_content, updated_policy)
    reencryption_time = time.time() - start_time

    # Re-Decryption
    start_time = time.time()
    redecrypted_content = cpabe.decrypt(public_key, updated_secret_key, updated_ciphertext)
    redecryption_time = time.time() - start_time

    return {
        'file_name': os.path.basename(file_path),
        'keygen_time': keygen_time,
        'encryption_time': encryption_time,
        'decryption_time': decryption_time,
        'rekeygen_time': rekeygen_time,
        'reencryption_time': reencryption_time,
        'redecryption_time': redecryption_time,
        'file_size': file_size,
        'file_read_time': file_read_time
    }

def main():
    # Initialize pairing group and CP-ABE scheme
    group = PairingGroup('SS512')
    cpabe = CPabe_BSW07(group)

    # Fixed number of attributes
    num_attributes = 5
    attributes = ['attribute{}'.format(i + 1) for i in range(num_attributes)]

    # Generate master and public keys
    master_key, public_key = cpabe.setup()

    # File to encrypt/decrypt
    file_path = 'key_user_1_aggregated.txt.bin'

    # Number of seconds to run the encryption process
    duration = int(input("Enter the number of seconds to run the encryption process: "))

    total_files_processed = 0
    start_time = time.time()
    while time.time() - start_time < duration:
        result = process_file(cpabe, public_key, master_key, file_path, attributes, num_attributes)
        if result:
            total_files_processed += 1

    print(f"Files processed in {duration} second(s): {total_files_processed}")

if __name__ == "__main__":
    main()

