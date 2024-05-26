from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, pair

# Initialize a pairing group
group = PairingGroup('SS512')

# Create some random elements
a = group.random(ZR)  # Random element in ZR
g = group.random(G1)  # Random element in G1

# Perform a pairing operation
result = pair(g, g ** a)

# Print the results
print("Random element in ZR:", a)
print("Random element in G1:", g)
print("Pairing result:", result)


