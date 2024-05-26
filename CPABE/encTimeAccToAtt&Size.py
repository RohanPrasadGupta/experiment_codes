from charm.toolbox.pairinggroup import PairingGroup, GT, G1, G2, ZR, pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEnc import ABEnc
import time
import random
import csv

class CPabe09(ABEnc):
    def __init__(self, groupObj):
        ABEnc.__init__(self)
        self.util = SecretUtil(groupObj, False)
        self.group = groupObj

    def setup(self):
        g1, g2 = self.group.random(G1), self.group.random(G2)
        alpha, a = self.group.random(ZR), self.group.random(ZR)
        e_gg_alpha = pair(g1, g2) ** alpha
        msk = {'g1^alpha': g1 ** alpha, 'g2^alpha': g2 ** alpha}
        pk = {'g1': g1, 'g2': g2, 'e(gg)^alpha': e_gg_alpha, 'g1^a': g1 ** a, 'g2^a': g2 ** a}
        return msk, pk

    def keygen(self, pk, msk, attributes):
        t = self.group.random(ZR)
        K = msk['g2^alpha'] * (pk['g2^a'] ** t)
        L = pk['g2'] ** t
        k_x = [self.group.hash(attr, G1) ** t for attr in attributes]
        K_x = {attr: k_x[i] for i, attr in enumerate(attributes)}
        return {'K': K, 'L': L, 'K_x': K_x, 'attributes': attributes}

    def encrypt(self, pk, M, policy_str):
        policy = self.util.createPolicy(policy_str)
        p_list = self.util.getAttributeList(policy)
        s = self.group.random(ZR)
        C_tilde = (pk['e(gg)^alpha'] ** s) * M
        C_0 = pk['g1'] ** s
        C = {}
        D = {}
        shares = self.util.calculateSharesList(s, policy)
        for i, attr in enumerate(p_list):
            r = self.group.random(ZR)
            C[attr] = ((pk['g1^a'] ** shares[i][1]) * (self.group.hash(attr, G1) ** -r))
            D[attr] = pk['g2'] ** r
        return {'C0': C_0, 'C': C, 'D': D, 'C_tilde': C_tilde, 'policy': policy_str, 'attribute': p_list}

    def decrypt(self, pk, sk, ct):
        policy = self.util.createPolicy(ct['policy'])
        pruned = self.util.prune(policy, sk['attributes'])
        if not pruned:
            return False
        coeffs = self.util.getCoefficients(policy)
        numerator = pair(ct['C0'], sk['K'])
        denominator = 1
        for i in pruned:
            j = i.getAttributeAndIndex()
            denominator *= (pair(ct['C'][j] ** coeffs[j], sk['L']) * pair(sk['K_x'][j] ** coeffs[j], ct['D'][j]))
        return ct['C_tilde'] / (numerator / denominator)

def main():
    group = PairingGroup('SS512')
    cpabe = CPabe09(group)
    msk, pk = cpabe.setup()

    csv_file = "cpabe_times.csv"
    with open(csv_file, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Number of Attributes", "File Size (bytes)", "Key Generation Time (s)", "Encryption Time (s)", "Decryption Time (s)"])

        num_attributes = 5  # Fixed number of attributes
        attr_list = ['ONE', 'THREE', 'TWO', 'THREE', 'FOUR', 'FIVE']  # Fixed attribute list

        for num_attr in range(1, 161):
            msg = group.random(GT)

            policy = '((ONE or THREE) and (TWO or FOUR))'
            start = time.time()
            cpkey, keygen_time = cpabe.keygen(pk, msk, attr_list), time.time() - start

            start = time.time()
            cipher, encrypt_time = cpabe.encrypt(pk, msg, policy), time.time() - start

            start = time.time()
            decrypted_msg, decrypt_time = cpabe.decrypt(pk, cpkey, cipher), time.time() - start

            assert decrypted_msg == msg, "Decryption failed"
            writer.writerow([num_attr, 48, keygen_time, encrypt_time, decrypt_time])

    print(f"Timings saved to {csv_file}")

if __name__ == '__main__':
    main()
