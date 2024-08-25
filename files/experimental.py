from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
import random
from pysnark.runtime import PrivVal, PubVal, snark
from pysnark.branching import if_then_else

def generate_keys():
    return [ECC.generate(curve='P-256') for _ in range(10)]

def hash_function(data):
    hasher = SHA256.new(data.encode())
    curve_order = int(ECC._curves['P-256'].p)
    return int(hasher.hexdigest(), 16) % curve_order

def create_commitment(data, secret):
    hasher = SHA256.new((data + str(secret)).encode())
    return int(hasher.hexdigest(), 16)

def sign_data(key, data):
    hasher = SHA256.new(data.encode())
    signer = DSS.new(key, 'fips-186-3')
    return signer.sign(hasher)

def verify_data(key, data, signature):
    hasher = SHA256.new(data.encode())
    verifier = DSS.new(key.public_key(), 'fips-186-3')
    try:
        verifier.verify(hasher, signature)
        return True
    except ValueError:
        return False

@snark
def prove_membership(accumulated_value, commitment, secret, pub_commitment):
    recalculated_commitment = create_commitment("input", secret)
    commitment_check = commitment == recalculated_commitment
    pub_commitment_check = commitment == pub_commitment
    return if_then_else(commitment_check, accumulated_value, 0)

# Initialize ECC key and use its public point as the base point
base_point = ECC.generate(curve='P-256').public_key().pointQ
accumulator = base_point * 0  # Start with the neutral element of the curve

# Simulating registration of outputs
users_keys = generate_keys()
secrets = [random.randint(1, 1 << 256) for _ in range(10)]  # Random secrets for commitments
outputs = [f"output-{random.randint(1000, 9999)}" for _ in range(10)]
commitments = [create_commitment(output, secrets[i]) for i, output in enumerate(outputs)]

accumulated_values = [accumulator]
witnesses = []

for commit in commitments:
    current_witness = accumulator
    witnesses.append(current_witness)  # Store this witness

    scaled_point = base_point * commit
    accumulator = accumulator + scaled_point
    accumulated_values.append(accumulator)

# Convert commitments and secrets to appropriate type for PySNARK
priv_commitments = [PrivVal(int(commitments[i])) for i in range(len(commitments))]
priv_secrets = [PrivVal(int(secrets[i])) for i in range(len(secrets))]
pub_commitments = [PubVal(int(commitments[i])) for i in range(len(commitments))]

# Convert accumulated values to public values for proof
pub_accumulated_values = [PubVal(int(accumulated_value.x)) for accumulated_value in accumulated_values]

membership_proofs = [prove_membership(pub_accumulated_values[i], priv_commitments[i], priv_secrets[i], pub_commitments[i]) for i in range(len(commitments))]

# Simulate delay for input registration
import time
time.sleep(2)

# Simulate registration of inputs
inputs = {i: f"input-related-to-output-{i}" for i in range(10) if random.choice([True, False])}
signatures = {i: sign_data(users_keys[i], inputs[i]) for i in inputs}

# Verify inputs
verified = {}
for i in signatures:
    if verify_data(users_keys[i], inputs[i], signatures[i]):
        verified[i] = commitments[i]

# Check the integrity of input and output registration
if len(verified) < len(commitments):
    pruned_commitments = {i: commitments[i] for i in range(10) if i not in verified}
else:
    pruned_commitments = {}

print(f"Total commitments: {len(commitments)}")
print(f"Verified inputs: {len(verified)}")
print(f"Pruned commitments: {len(pruned_commitments)}")

print("Non-Pruned Outputs:")
for i in range(10):
    if i not in pruned_commitments:
        status = "Verified" if i in verified else "Unverified"
        witness_point = witnesses[i]
        acc_point = accumulated_values[i+1]  # Access the updated accumulator state
        print(f"Output {i+1}: {outputs[i]}, Status: {status}, Witness: ({witness_point.x}, {witness_point.y}), Accumulated Value: ({acc_point.x}, {acc_point.y})")
