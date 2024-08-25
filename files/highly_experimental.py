from Crypto.Hash import SHA256
import random
from pysnark.runtime import PrivVal, PubVal, snark
from pysnark.branching import if_then_else

def hash_function(data):
    hasher = SHA256.new(data.encode())
    return int(hasher.hexdigest(), 16)

def create_commitment(output, secret):
    output_hash = hash_function(output)
    combined_data = f"{{{output_hash}}}-{{{secret}}}"
    res = hash_function(str(combined_data))
    return res

def schnorr_commitment(g, x, p):
    r = random.randint(1, p-1)
    t = pow(g, r, p)
    return r, t

def schnorr_proof(g, t, r, x, p, q):
    c = hash_function(f"{t}{x}")
    z = (r + c * x) % q
    return c, z

def modular_exponentiation(base, exponent, modulus):
    result = 1
    base = base % modulus
    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        exponent = exponent >> 1
        base = (base * base) % modulus
    return result

p = 23  # A small prime number for demonstration
g = 5   # A generator for the group
q = p - 1  # Order of the group

secrets = [random.randint(1, 1000) for _ in range(10)]
outputs = [f"output-{random.randint(1000, 9999)}" for _ in range(10)]
commitments = [create_commitment(outputs[i], secrets[i]) for i in range(10)]
pub_commitments = [PubVal(commitment) for commitment in commitments]

public_keys = [PubVal(modular_exponentiation(g, secrets[i], p)) for i in range(10)]

@snark
def modular_exponentiation_snark(base, exponent, modulus):
    result = PrivVal(1)
    base = base % modulus

    exp_bits = exponent.to_bits(bits=256)  # Handle large exponent bits

    for bit in exp_bits:
        result = (result * result) % modulus
        result = if_then_else(bit, (result * base) % modulus, result)
    
    return result

@snark
def verify_commitment(pub_commitment, t, c, z, output_hash, pub_key, recalculated_commitment):
    g_z = modular_exponentiation_snark(PrivVal(g), z, p)  # This represents g^z mod p in SNARK-compatible terms
    y_c = (t * modular_exponentiation_snark(pub_key, c, p)) % p  # This represents t * y^c mod p in SNARK-compatible terms
    
    schnorr_result = (g_z == y_c)
    return (pub_commitment == recalculated_commitment) & schnorr_result

verification_attempts = [random.choice([True, False]) for _ in range(10)]
zk_proofs = []

for i in range(len(outputs)):
    if verification_attempts[i]:
        output_hash = hash_function(outputs[i])
        priv_output_hash = PrivVal(output_hash)
        r, t = schnorr_commitment(g, secrets[i], p)
        c, z = schnorr_proof(g, t, r, secrets[i], p, q)
        pub_key = public_keys[i]
        recalculated_commitment = PubVal(create_commitment(outputs[i], secrets[i]))
        zk_proofs.append((i, verify_commitment(pub_commitments[i], t, PrivVal(c), PrivVal(z), priv_output_hash, pub_key, recalculated_commitment)))
    else:
        zk_proofs.append((i, None))

verified = {}
pruned_commitments = {}
for i, proof in zk_proofs:
    if proof is not None and proof:
        verified[i] = commitments[i]
    else:
        pruned_commitments[i] = commitments[i]

print("Zero-Knowledge Proofs and Statuses:")
for i, proof in zk_proofs:
    status = "Verified" if proof is not None and proof else "Not verified"
    print(f"Commitment {i}: Proof Provided: {'Yes' if verification_attempts[i] else 'No'}, Status: {status}")

print("Pruned Outputs:")
for i in pruned_commitments:
    print(f"Output {i+1}: {outputs[i]} was pruned due to unverified or no proof provided.")
