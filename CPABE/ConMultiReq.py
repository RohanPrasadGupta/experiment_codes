from charm.toolbox.pairinggroup import PairingGroup
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
import time
import csv
import os


def create_policy(num_attributes):
    """Creates a policy string with the specified number of attributes joined by 'or'."""
    return ' or '.join(['attribute{}'.format(i + 1) for i in range(num_attributes)])


def process_file(cpabe, public_key, master_key, file_path, attributes, num_attributes):
    """Processes a single file: reads, encrypts, decrypts, and logs times."""
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

    return [os.path.basename(file_path), keygen_time, encryption_time, decryption_time,
            rekeygen_time, reencryption_time, redecryption_time, file_size, file_read_time]


def main():
    # Initialize pairing group and CP-ABE scheme
    group = PairingGroup('SS512')
    cpabe = CPabe_BSW07(group)

    # Fixed number of attributes
    num_attributes = 20
    attributes = ['attribute{}'.format(i + 1) for i in range(num_attributes)]

    # Generate master and public keys
    master_key, public_key = cpabe.setup()

    # Directory containing files to encrypt/decrypt
    folder_path = 'ConReq'
    files = [os.path.join(folder_path, file) for file in os.listdir(folder_path) if
             os.path.isfile(os.path.join(folder_path, file))]

    # CSV file to store the results
    csv_file_name = 'encryption_results_100000.csv'

    # Number of times to perform the task
    repetitions = 100000

    with open(csv_file_name, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['Repetition', 'File Name', 'Key Generation Time', 'Encryption Time', 'Decryption Time',
                         'Re-Key Generation Time', 'Re-Encryption Time', 'Re-Decryption Time',
                         'File Size (bytes)', 'File Read Time'])

        for repetition in range(1, repetitions + 1):
            for file_path in files:
                result = process_file(cpabe, public_key, master_key, file_path, attributes, num_attributes)
                if result:
                    writer.writerow([repetition] + result)

    print(f"Simulation complete. Results written to {csv_file_name}")


if __name__ == "__main__":
    main()
