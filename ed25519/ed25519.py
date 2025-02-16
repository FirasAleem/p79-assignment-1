import os
import hashlib
from x25519.utils import mult_inverse
from ed25519.utils import ( 
    edwards_point_add_extended, 
    edwards_scalar_mult, 
    encode_edwards_point, 
    decode_edwards_point, 
    affine_to_extended, 
    normalize_extended, 
    edwards_point_negate, 
    is_identity,
    )

# The prime modulus (same as for Curve25519)
P = 2**255 - 19

# Compute d = -121665/121666 mod P (for Ed25519, a = -1)
d = (-121665 * mult_inverse(121666, P)) % P

# Order of the base-point subgroup (a prime number)
L = 2**252 + 27742317777372353535851937790883648493

# Base point for Ed25519 (affine coordinates, as specified in RFC 8032)
B = (
    15112221349535400772501151409588531511454012693041857206046113283949847762202,
    46316835694926478169428394003475163141307993866256225615783033603165251855960,
)


class Ed25519:
    """
    An implementation of Ed25519 for key generation, signing, and verification
    """

    def __init__(self):
        self.P = P
        self.d = d
        self.L = L
        self.B = affine_to_extended(B) 

    def generate_private_key(self) -> bytes:
        """Generate a random 32-byte private key."""
        return os.urandom(32)

    def generate_public_key(self, private_key: bytes) -> bytes:
        """
        Derive a public key from a private key:
            1. Hash the 32-byte private key with SHA-512.
            2. Clamp the lower 32 bytes to derive the scalar 'a'.
            3. Compute A = a * B (using Edwards scalar multiplication).
            4. Return the compressed encoding of A.
        """
        # Step 1
        h_full = hashlib.sha512(private_key).digest()
        key = bytearray(h_full[:32])
        # Step 2 Clamping
        key[0] &= 248     # Clear the lowest 3 bits of the first byte
        key[31] &= 127    # Clear the highest bit of the last byte
        key[31] |= 64     # Set the second-highest bit of the last byte

        a = int.from_bytes(key, "little")
        A_point = edwards_scalar_mult(a, self.B)
        return encode_edwards_point(A_point)

    def sign(self, private_key: bytes, message: bytes) -> bytes:
        """
        Sign a message using Ed25519:
        
            1. Compute H = SHA-512(private_key), split into lower 32 bytes and prefix.
            2. Clamp the lower half to obtain the scalar 'a'.
            3. Compute A = a * B.
            4. Compute r = SHA-512(prefix || message) mod L.
            5. Compute R = r * B.
            6. Compute hram = SHA-512(encode(R) || encode(A) || message) mod L.
            7. Compute S = (r + hram * a) mod L.
            8. Return the 64-byte signature: encode(R) || S.
        """
        # Step 1
        h_full = hashlib.sha512(private_key).digest()
        key = bytearray(h_full[:32])
        # Step 2: Clamping
        key[0] &= 248     # Clear the lowest 3 bits of the first byte
        key[31] &= 127    # Clear the highest bit of the last byte
        key[31] |= 64     # Set the second-highest bit of the last byte

        a = int.from_bytes(key, "little")
        prefix = h_full[32:]
        
        # Step 3
        A_point = edwards_scalar_mult(a, self.B)
        # print(f"A_point: {A_point}")
        # A_point = normalize_extended(A_point)
        # print(f"A_point normalized: {A_point}")
        A_enc = encode_edwards_point(A_point)
        
        # Step 4
        r = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % self.L
        
        # Step 5
        R_point = edwards_scalar_mult(r, self.B)
        # print(f"R_point: {R_point}")
        # R_point = normalize_extended(R_point)
        # print(f"R_point normalized: {R_point}")
    
        R_enc = encode_edwards_point(R_point)
        
        # Step 6
        hram = int.from_bytes(hashlib.sha512(R_enc + A_enc + message).digest(), "little") % self.L
        
        # Step 7
        S = (r + hram * a) % self.L
        S_enc = S.to_bytes(32, "little")
        
        print (f"R_enc: {R_enc}")
        print (f"S_enc: {S_enc}")
        return R_enc + S_enc

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """
        Verify an Ed25519 signature:
        
        1. Split the 64-byte signature into R (first 32 bytes) and S (last 32 bytes).
        2. Decode R and the public key A.
        3. Compute hram = SHA-512(encode(R) || public_key || message) mod L.
        4. Verify that S * B == R + hram * A.
        """
        if len(signature) != 64:
            return False
        # Step 1
        R_enc = signature[:32]
        S_enc = signature[32:]
        
        print(f"R_enc verify: {R_enc}")
        print(f"S_enc verify: {S_enc}")
        
        s_int = int.from_bytes(S_enc, "little")
        # Reject if s is not canonical
        if s_int >= self.L:
            return False

        try:
            # Step 2
            R_point = decode_edwards_point(R_enc)
            print(f"R_point verify: {R_point}")
            A_point = decode_edwards_point(public_key)
            print(f"A_point verify: {A_point}")
        except Exception:
            return False

        # Step 3
        hram = int.from_bytes(hashlib.sha512(R_enc + public_key + message).digest(), "little") % self.L
        
        # Compute sB and kA.
        sB = edwards_scalar_mult(s_int, self.B)
        hA = edwards_scalar_mult(hram, A_point)
        
        # Compute P = sB - kA.
        point = edwards_point_add_extended(sB, edwards_point_negate(hA))
        
        # Multiply both sides by 8.
        eight_R = edwards_scalar_mult(8, R_point)
        eight_P = edwards_scalar_mult(8, point)
        
        return normalize_extended(eight_R) == normalize_extended(eight_P)

        # This is the unbatched verification code
        # # Step 4
        # S = s_int % self.L
        # SB_point = edwards_scalar_mult(S, self.B)
        
        # hA_point = edwards_scalar_mult(hram, A_point)
        # R_calc = edwards_point_add_extended(R_point, hA_point)
        
        # print(f"SB_point: {normalize_extended(SB_point)}")
        # print(f"R_calc: {normalize_extended(R_calc)}")
        
        # return normalize_extended(SB_point) == normalize_extended(R_calc)


    def verify_batch(self, batch: list[tuple[bytes, bytes, bytes]]) -> bool:
        """
        Batch verification.
        'batch' is a list of tuples (public_key, message, signature).
        For each signature, we check that:
            [8]([s]B - [k]A) - [8]R == identity
        Then we form a random linear combination of these terms and verify
        that the sum is the identity.
        """
        # Accumulator for the linear combination
        accumulated = None

        for (public_key, message, signature) in batch:
            # Check signature length.
            if len(signature) != 64:
                return False

            R_enc = signature[:32]
            S_enc = signature[32:]
            
            # Parse S without reducing modulo L
            s_int = int.from_bytes(S_enc, "little")
            if s_int >= self.L:
                return False  # Noncanonical s
            
            # Decode R and A.
            try:
                R_point = decode_edwards_point(R_enc)
                A_point = decode_edwards_point(public_key)
            except Exception:
                return False
            
            # Compute challenge: k = H(R || public_key || message) mod L.
            hram = int.from_bytes(hashlib.sha512(R_enc + public_key + message).digest(), "little") % self.L
            
            # Compute [s]B and [k]A.
            sB = edwards_scalar_mult(s_int, self.B)
            kA = edwards_scalar_mult(hram, A_point)
            # Compute T = [s]B - [k]A.
            T = edwards_point_add_extended(sB, edwards_point_negate(kA))
            # Compute verification term: U = [8]T - [8]R.
            U = edwards_point_add_extended(
                    edwards_scalar_mult(8, T),
                    edwards_point_negate(edwards_scalar_mult(8, R_point))
                )
            # Choose a random scalar z for this signature (nonzero modulo L).
            z = int.from_bytes(os.urandom(32), "little") % self.L
            if z == 0:
                z = 1

            # Multiply U by z.
            weighted_U = edwards_scalar_mult(z, U)
            
            # Accumulate the weighted terms.
            if accumulated is None:
                accumulated = weighted_U
            else:
                accumulated = edwards_point_add_extended(accumulated, weighted_U)

        # Finally, check that the accumulated term is the identity.
        # If the batch is empty, we can consider it valid.
        if accumulated is None:
            return True
        return is_identity(accumulated)
