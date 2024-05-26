from charm.toolbox.pairinggroup import PairingGroup
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
import time
import csv
import os

def create_policy(num_attributes):
    return ' or '.join(['attribute{}'.format(i+1) for i in range(num_attributes)])

group = PairingGroup('SS512')
cpabe = CPabe_BSW07(group)

total_attributes = 20

attributes = ['attribute{}'.format(i+1) for i in range(total_attributes)]
(master_key, public_key) = cpabe.setup()
max_attributes = 160
file_name = 'key_user_1_auth_EMP014_EMP065_EMP019_EMP003_EMP069_EMP045_EMP059_EMP009_EMP033_aggregated.txt.bin'
with open(file_name, 'rb') as f:
    file_content = f.read()

file_size = os.path.getsize(file_name)

with open('key_user_1_auth_EMP008_EMP004(2).csv', mode='w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(['Number of Attributes', 'Key Generation Time', 'Encryption Time', 'Decryption Time', 'Re-Key Generation Time', 'Re-Encryption Time', 'Re-Decryption Time', 'File Size (bytes)'])

    for num_attrs in range(1, max_attributes + 1):
        policy = create_policy(num_attrs)

        start_time = time.time()
        secret_key = cpabe.keygen(public_key, master_key, attributes[:num_attrs])
        keygen_time = time.time() - start_time

        start_time = time.time()
        ciphertext = cpabe.encrypt(public_key, file_content, policy)
        encryption_time = time.time() - start_time

        start_time = time.time()
        decrypted_content = cpabe.decrypt(public_key, secret_key, ciphertext)
        decryption_time = time.time() - start_time

        updated_policy = create_policy(num_attrs - 1) if num_attrs > 1 else 'attribute1'

        start_time = time.time()
        updated_secret_key = cpabe.keygen(public_key, master_key, attributes[:num_attrs-1])
        rekeygen_time = time.time() - start_time

        start_time = time.time()
        updated_ciphertext = cpabe.encrypt(public_key, file_content, updated_policy)
        reencryption_time = time.time() - start_time

        start_time = time.time()
        redecrypted_content = cpabe.decrypt(public_key, updated_secret_key, updated_ciphertext)
        redecryption_time = time.time() - start_time

        writer.writerow([num_attrs, keygen_time, encryption_time, decryption_time, rekeygen_time, reencryption_time, redecryption_time, file_size])

print("Simulation complete. Results written to key_user_1_auth_EMP008_EMP004.csv")
