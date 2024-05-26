from charm.toolbox.pairinggroup import PairingGroup, GT
from charm.schemes.abenc import abenc_bsw07  # Adjust the import to the ABE scheme you choose
import time

def setup_abe(group):
    abe = abenc_bsw07.CPabe_BSW07(group)
    public_key, master_key = abe.setup()
    return abe, public_key, master_key

def encrypt_message(abe, public_key, message, attributes):
    policy = " or ".join(attributes)
    start_time = time.time()
    ciphertext = abe.encrypt(public_key, message, policy)
    end_time = time.time()
    return ciphertext, end_time - start_time

def main():
    group = PairingGroup('SS512')
    abe, public_key, master_key = setup_abe(group)
    message = group.random(GT)

    all_attributes = ['attr1']*20

    for i in range(1, len(all_attributes) + 1):
        attributes = all_attributes[:i]
        _, encryption_time = encrypt_message(abe, public_key, message, attributes)
        print(f"Encryption time with {i} attributes: {encryption_time:.6f} seconds")

if __name__ == "__main__":
    main()
