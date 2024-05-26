import csv
import os
from charm.toolbox.pairinggroup import PairingGroup, GT
from charm.schemes.abenc import abenc_bsw07
import time


def setup_abe(group):
    abe = abenc_bsw07.CPabe_BSW07(group)
    start_time = time.time()
    public_key, master_key = abe.setup()
    end_time = time.time()
    return abe, public_key, master_key, end_time - start_time


def keygen_abe(abe, master_key, attributes):
    start_time = time.time()
    user_key = abe.keygen(master_key, attributes)
    end_time = time.time()
    return user_key, end_time - start_time


def construct_policy(attributes):
    policy = " or ".join(attributes)
    return policy


def get_file_size(file_path):
    return os.path.getsize(file_path)


def encrypt_file(abe, public_key, file_content, policy):
    start_time = time.time()
    ciphertext = abe.encrypt(public_key, file_content, policy)
    end_time = time.time()
    return ciphertext, end_time - start_time


def decrypt_file(abe, public_key, user_key, ciphertext):
    start_time = time.time()
    try:
        decrypted_file = abe.decrypt(public_key, user_key, ciphertext)
    except Exception as e:
        print(f"Decryption failed: {e}")
        return None, 0
    end_time = time.time()
    return decrypted_file, end_time - start_time


def main():
    group = PairingGroup('SS512')
    abe, public_key, master_key, setup_time = setup_abe(group)

    file_path = 'user_1_merged_1.txt'
    with open(file_path, 'rb') as file:
        file_content = file.read()

    file_size = get_file_size(file_path)

    num_attributes = 20
    all_attributes = [f'attr{i}' for i in range(1, num_attributes + 1)]

    with open('encryption_report.csv', mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['Number of Attributes', 'Policy', 'File Size (bytes)', 'Key Generation Time (seconds)',
                         'Encryption Time (seconds)', 'Decryption Time (seconds)'])

        for i in range(1, num_attributes + 1):
            attributes = all_attributes[:i]
            user_key, keygen_time = keygen_abe(abe, master_key, attributes)

            policy = construct_policy(attributes)
            ciphertext, encryption_time = encrypt_file(abe, public_key, file_content, policy)
            decrypted_file, decryption_time = decrypt_file(abe, public_key, user_key, ciphertext)

            writer.writerow([i, policy, file_size, keygen_time, encryption_time, decryption_time])

            print(
                f"With {i} attributes, policy '{policy}', and file size {file_size} bytes: Key Generation time = {keygen_time:.6f} seconds, Encryption time = {encryption_time:.6f} seconds, Decryption time = {decryption_time:.6f} seconds")


if __name__ == "__main__":
    main()
