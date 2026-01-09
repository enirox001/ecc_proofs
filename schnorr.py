"""
Schnorr Signature Implementation
Educational implementation - DO NOT use in production!
"""

import hashlib
import secrets
from dataclasses import dataclass
from typing import Tuple

# Using a small prime for educational purposes
# (Real Bitcoin uses secp256k1 with ~256-bit numbers)
P = 2**256 - 2**32 - 977  # secp256k1 field prime


class Point:
    """Represents a point on an elliptic curve y² = x³ + 7 (secp256k1)"""
    
    def __init__(self, x: int, y: int):
        self.x = x % P
        self.y = y % P
    
    def __eq__(self, other):
        if isinstance(other, Point):
            return self.x == other.x and self.y == other.y
        return False
    
    def __add__(self, other):
        """Point addition on elliptic curve"""
        if self == Point.infinity():
            return other
        if other == Point.infinity():
            return self
        
        if self.x == other.x:
            if self.y == other.y:
                # Point doubling
                s = (3 * self.x * self.x * pow(2 * self.y, -1, P)) % P
            else:
                return Point.infinity()
        else:
            # Point addition
            s = ((other.y - self.y) * pow(other.x - self.x, -1, P)) % P
        
        x = (s * s - self.x - other.x) % P
        y = (s * (self.x - x) - self.y) % P
        return Point(x, y)
    
    def __mul__(self, scalar: int):
        """Scalar multiplication: scalar * Point"""
        result = Point.infinity()
        addend = self
        
        while scalar:
            if scalar & 1:
                result = result + addend
            addend = addend + addend
            scalar >>= 1
        
        return result
    
    def __rmul__(self, scalar: int):
        return self.__mul__(scalar)
    
    @staticmethod
    def infinity():
        """The point at infinity (identity element)"""
        return Point(0, 0)
    
    def __repr__(self):
        if self == Point.infinity():
            return "Point(∞)"
        return f"Point({hex(self.x)[:16]}..., {hex(self.y)[:16]}...)"


# secp256k1 generator point
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = Point(Gx, Gy)

# Order of the generator (number of points it generates)
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


@dataclass
class PrivateKey:
    """Schnorr private key"""
    secret: int  # x
    
    def public_key(self) -> 'PublicKey':
        """Derive public key: X = x·G"""
        return PublicKey(self.secret * G)


@dataclass
class PublicKey:
    """Schnorr public key"""
    point: Point  # X
    
    def to_bytes(self) -> bytes:
        """Serialize public key (x-coordinate only, compressed)"""
        return self.point.x.to_bytes(32, 'big')


@dataclass
class Signature:
    """Schnorr signature (R, s)"""
    R: Point  # Commitment point
    s: int    # Signature scalar
    
    def to_bytes(self) -> bytes:
        """Serialize signature"""
        R_bytes = self.R.x.to_bytes(32, 'big')
        s_bytes = self.s.to_bytes(32, 'big')
        return R_bytes + s_bytes
    
    @staticmethod
    def from_bytes(data: bytes) -> 'Signature':
        """Deserialize signature"""
        R_x = int.from_bytes(data[:32], 'big')
        s = int.from_bytes(data[32:64], 'big')
        
        # Recover y-coordinate from x (simplified)
        y_squared = (pow(R_x, 3, P) + 7) % P
        R_y = pow(y_squared, (P + 1) // 4, P)
        
        return Signature(Point(R_x, R_y), s)


def hash_to_scalar(data: bytes) -> int:
    """Hash data to a scalar in the field"""
    h = hashlib.sha256(data).digest()
    return int.from_bytes(h, 'big') % n


def generate_keypair() -> Tuple[PrivateKey, PublicKey]:
    """
    Generate a new Schnorr key pair
    
    Returns:
        (private_key, public_key)
    """
    # Generate random private key
    x = secrets.randbelow(n - 1) + 1
    private_key = PrivateKey(x)
    public_key = private_key.public_key()
    
    print(f"🔑 Generated keypair:")
    print(f"   Private key (x): {hex(x)[:32]}...")
    print(f"   Public key (X):  {public_key.point}")
    
    return private_key, public_key


def sign(message: bytes, private_key: PrivateKey, public_key: PublicKey) -> Signature:
    """
    Create a Schnorr signature
    
    Steps:
    1. Generate random nonce r
    2. Compute R = r·G
    3. Compute challenge c = Hash(X || R || m)
    4. Compute s = r + c·x
    5. Return (R, s)
    
    Args:
        message: The message to sign
        private_key: Signer's private key
        public_key: Signer's public key
    
    Returns:
        Signature (R, s)
    """
    print(f"\n📝 Signing message: {message}")
    
    # Step 1: Generate random nonce
    r = secrets.randbelow(n - 1) + 1
    print(f"   1. Generated nonce r: {hex(r)[:32]}...")
    
    # Step 2: Compute commitment R = r·G
    R = r * G
    print(f"   2. Computed R = r·G: {R}")
    
    # Step 3: Compute challenge c = Hash(X || R || m)
    # This is the "key-prefixed" variant from the paper
    hash_input = (public_key.to_bytes() + 
                  R.x.to_bytes(32, 'big') + 
                  message)
    c = hash_to_scalar(hash_input)
    print(f"   3. Computed challenge c = Hash(X||R||m): {hex(c)[:32]}...")
    
    # Step 4: Compute signature scalar s = r + c·x (mod n)
    s = (r + c * private_key.secret) % n
    print(f"   4. Computed s = r + c·x: {hex(s)[:32]}...")
    
    signature = Signature(R, s)
    print(f"   ✅ Signature created: (R, s)")
    
    return signature


def verify(message: bytes, signature: Signature, public_key: PublicKey) -> bool:
    """
    Verify a Schnorr signature
    
    Check: s·G ?= R + c·X
    where c = Hash(X || R || m)
    
    Args:
        message: The message that was signed
        signature: The signature (R, s)
        public_key: Signer's public key
    
    Returns:
        True if signature is valid, False otherwise
    """
    print(f"\n🔍 Verifying signature for message: {message}")
    
    # Step 1: Recompute challenge c = Hash(X || R || m)
    hash_input = (public_key.to_bytes() + 
                  signature.R.x.to_bytes(32, 'big') + 
                  message)
    c = hash_to_scalar(hash_input)
    print(f"   1. Recomputed challenge c: {hex(c)[:32]}...")
    
    # Step 2: Compute left side: s·G
    left_side = signature.s * G
    print(f"   2. Computed s·G: {left_side}")
    
    # Step 3: Compute right side: R + c·X
    right_side = signature.R + (c * public_key.point)
    print(f"   3. Computed R + c·X: {right_side}")
    
    # Step 4: Check if they're equal
    valid = left_side == right_side
    
    if valid:
        print(f"   ✅ Signature is VALID!")
        print(f"      s·G == R + c·X ✓")
    else:
        print(f"   ❌ Signature is INVALID!")
        print(f"      s·G != R + c·X ✗")
    
    return valid


def demonstrate_schnorr():
    """Demonstrate Schnorr signature creation and verification"""
    
    print("=" * 70)
    print("SCHNORR SIGNATURE DEMONSTRATION")
    print("=" * 70)
    
    # Generate keys
    print("\n" + "─" * 70)
    print("STEP 1: KEY GENERATION")
    print("─" * 70)
    private_key, public_key = generate_keypair()
    
    # Sign a message
    print("\n" + "─" * 70)
    print("STEP 2: SIGNING")
    print("─" * 70)
    message = b"Hello, Schnorr signatures!"
    signature = sign(message, private_key, public_key)
    
    # Verify the signature
    print("\n" + "─" * 70)
    print("STEP 3: VERIFICATION")
    print("─" * 70)
    is_valid = verify(message, signature, public_key)
    
    # Try tampering
    print("\n" + "─" * 70)
    print("STEP 4: TAMPERED MESSAGE TEST")
    print("─" * 70)
    tampered_message = b"Hello, tampered message!"
    print(f"🔧 Attempting to verify with different message...")
    is_valid_tampered = verify(tampered_message, signature, public_key)
    
    # Try forging
    print("\n" + "─" * 70)
    print("STEP 5: FORGERY ATTEMPT")
    print("─" * 70)
    print(f"😈 Evil attacker tries to forge signature...")
    fake_r = secrets.randbelow(n - 1) + 1
    fake_R = fake_r * G
    fake_s = secrets.randbelow(n - 1) + 1
    fake_signature = Signature(fake_R, fake_s)
    print(f"   Created fake signature with random values")
    is_valid_forged = verify(message, fake_signature, public_key)
    
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"✅ Original signature valid: {is_valid}")
    print(f"❌ Tampered message valid: {is_valid_tampered}")
    print(f"❌ Forged signature valid: {is_valid_forged}")
    print("=" * 70)


if __name__ == "__main__":
    demonstrate_schnorr()
