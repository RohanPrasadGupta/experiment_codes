from charm.toolbox.pairinggroup import PairingGroup
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
import time
import csv
import os

# Initialize pairing group
group = PairingGroup('SS512')

# Initialize CP-ABE scheme
cpabe = CPabe_BSW07(group)

# Define attributes
attributes = ['attribute1', 'attribute2', 'attribute3', 'attribute4', 'attribute5','attribute6','attribute7']

# Generate master key and public key
(master_key, public_key) = cpabe.setup()

# Measure key generation time
start_time = time.time()
secret_key = cpabe.keygen(public_key, master_key, attributes)
keygen_time = time.time() - start_time

# Define your policy
policy = 'attribute1 and attribute2 and attribute3 or attribute4 and attribute5 or attribute6 and attribute2'

# Count the number of unique attributes in the policy
unique_attributes = len(set(policy.replace('and', '').replace('or', '').split()))

# Read the file content
file_name = 'user_1_merged_1.txt'
with open(file_name, 'rb') as f:
    file_content = f.read()

# Get the file size
file_size = os.path.getsize(file_name)

# Encrypt the file content
start_time = time.time()
ciphertext = cpabe.encrypt(public_key, file_content, policy)
encryption_time = time.time() - start_time

# Decrypt the file content
start_time = time.time()
decrypted_content = cpabe.decrypt(public_key, secret_key, ciphertext)
decryption_time = time.time() - start_time

# Write results to a CSV file
with open('Trial2.csv', mode='w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(['File Size (bytes)', 'Key Generation Time', 'Encryption Time', 'Decryption Time', 'Number of Attributes'])
    writer.writerow([file_size, keygen_time, encryption_time, decryption_time, unique_attributes])

print("Results written to Trial2.csv")
