#!/usr/bin/env python3
"""
Generate RSA 4096-bit key pair for student identity.

This script creates:
- student_private.pem: Student's private key (MUST commit to Git)
- student_public.pem: Student's public key (MUST commit to Git)

Key Requirements:
- Key size: 4096 bits
- Public exponent: 65537 (standard)
- Format: PEM (Privacy-Enhanced Mail)
"""

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


def generate_rsa_keypair(key_size: int = 4096):
    """
    Generate RSA key pair with specified key size.
    
    Args:
        key_size: Size of RSA key in bits (default: 4096)
    
    Returns:
        Tuple of (private_key, public_key) objects
    """
    # Generate RSA private key
    # - Key size: 4096 bits (required)
    # - Public exponent: 65537 (standard, widely used)
    # - Backend: default cryptography backend
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    
    # Extract public key from private key
    public_key = private_key.public_key()
    
    return private_key, public_key


def save_private_key(private_key, filepath: str):
    """
    Save private key to PEM file.
    
    Args:
        private_key: RSA private key object
        filepath: Path to save the private key
    """
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    with open(filepath, 'wb') as f:
        f.write(pem)
    
    print(f"✅ Private key saved to: {filepath}")


def save_public_key(public_key, filepath: str):
    """
    Save public key to PEM file.
    
    Args:
        public_key: RSA public key object
        filepath: Path to save the public key
    """
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    with open(filepath, 'wb') as f:
        f.write(pem)
    
    print(f"✅ Public key saved to: {filepath}")


def main():
    """
    Main function to generate and save RSA key pair.
    """
    print("🔐 Generating RSA 4096-bit key pair...")
    
    # Generate keys
    private_key, public_key = generate_rsa_keypair(key_size=4096)
    
    # Save to files
    save_private_key(private_key, "student_private.pem")
    save_public_key(public_key, "student_public.pem")
    
    print("\n✅ Key pair generation complete!")
    print("📝 Files created:")
    print("   - student_private.pem (private key - MUST commit)")
    print("   - student_public.pem (public key - MUST commit)")
    print("\n⚠️  Security Warning:")
    print("   These keys will be PUBLIC in your GitHub repository.")
    print("   DO NOT reuse these keys for any other purpose.")


if __name__ == "__main__":
    main()
