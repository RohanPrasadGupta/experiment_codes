from charm.toolbox.pairinggroup import PairingGroup, GT
from charm.schemes.abenc import abenc_waters09 as waters09
import time
import random
import csv

class CPabe09(waters09.CPabe09):
    def __init__(self, groupObj):
        super().__init__(groupObj)

    def setup(self):
        start_time = time.time()
        msk, pk = super().setup()
        end_time = time.time()
        return msk, pk, end_time - start_time

    def keygen(self, pk, msk, attributes):
        start_time = time.time()
        key = super().keygen(pk, msk, attributes)
        end_time = time.time()
        return key, end_time - start_time

    def encrypt(self, pk, M, policy_str):
        start_time = time.time()
        ct = super().encrypt(pk, M, policy_str)
        end_time = time.time()
        return ct, end_time - start_time

    def decrypt(self, pk, sk, ct):
        start_time = time.time()
        result = super().decrypt(pk, sk, ct)
        end_time = time.time()
        return result, end_time - start_time

def generate_attributes(num_attributes, max_attr=100):
    return ['ATTR' + str(i) for i in random.sample(range(max_attr), num_attributes)]

def main():
    group = PairingGroup('SS512')
    cpabe = CPabe09(group)
    msk, pk, setup_time = cpabe.setup()

    policy = '((ONE or THREE) and (TWO or FOUR))'  # Example policy
    msg = group.random(GT)

    # Prepare CSV file
    csv_file = "cpabe_times.csv"
    with open(csv_file, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Number of Attributes", "Key Generation Time (s)",
                         "Encryption Time (s)", "Decryption Time (s)"])

        for num_attr in range(101):  # Range from 0 to 100
            attr_list = generate_attributes(num_attr)
            cpkey, keygen_time = cpabe.keygen(pk, msk, attr_list)
            cipher, encryption_time = cpabe.encrypt(pk, msg, policy)
            decrypted_msg, decryption_time = cpabe.decrypt(pk, cpkey, cipher)

            # Write to CSV file
            writer.writerow([num_attr, keygen_time, encryption_time, decryption_time])
            print(f'Processed {num_attr} attributes')

    print(f"Data written to {csv_file}")

if __name__ == '__main__':
    main()
