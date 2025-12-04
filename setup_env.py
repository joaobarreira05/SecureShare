import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_rsa_keys():
    print("Generating RSA Key Pair (4096 bits)...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Escape newlines for .env
    private_key_str = private_pem.decode('utf-8').replace('\n', '\\n')
    public_key_str = public_pem.decode('utf-8').replace('\n', '\\n')
    
    return private_key_str, public_key_str

def setup_env():
    if os.path.exists(".env"):
        response = input("A .env file already exists. Overwrite it? (y/N): ")
        if response.lower() != 'y':
            print("Aborted.")
            return

    if not os.path.exists(".env.example"):
        print("Error: .env.example not found.")
        return

    print("Reading .env.example...")
    with open(".env.example", "r") as f:
        env_content = f.read()

    private_key, public_key = generate_rsa_keys()

    # Replace placeholders (or append if not present in example as placeholders)
    # Since .env.example has empty strings for keys, we can replace them using string formatting or simple replacement if we know the structure.
    # A robust way is to append or replace specific lines.
    
    new_lines = []
    for line in env_content.splitlines():
        if line.startswith("SERVER_PRIVATE_KEY="):
            new_lines.append(f'SERVER_PRIVATE_KEY="{private_key}"')
        elif line.startswith("SERVER_PUBLIC_KEY="):
            new_lines.append(f'SERVER_PUBLIC_KEY="{public_key}"')
        else:
            new_lines.append(line)
            
    with open(".env", "w") as f:
        f.write("\n".join(new_lines))
        f.write("\n") # Ensure trailing newline

    print("SUCCESS: .env file created with new RSA keys.")

if __name__ == "__main__":
    setup_env()
