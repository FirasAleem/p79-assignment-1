import unittest
import random
import time
from x25519.x25519 import X25519
from nacl.bindings import crypto_scalarmult


class TestX25519(unittest.TestCase):
    def setUp(self):
        """Set up the X25519 class with both 'ladder' and 'double_and_add' methods."""
        self.x25519_ladder = X25519(method='ladder')
        self.x25519_double_add = X25519(method='double_and_add')

    def test_scalar_multiply_maximum(self):
        """Test scalar multiplication with the maximum possible scalar and validate against PyNaCl."""
        max_scalar = (1 << 255) - 1
        max_scalar_bytes = max_scalar.to_bytes(32, 'little')
        public_key = b'\x09' + b'\x00' * 31  # Base point

        # X25519 implementation
        result_x = self.x25519_ladder.scalar_multiply(max_scalar_bytes, public_key)
        
        # Use PyNaCl for reference
        expected_output = crypto_scalarmult(max_scalar_bytes, public_key)
        
        print(f"Result for max scalar: {result_x.hex()}")
        print(f"Expected (PyNaCl) result: {expected_output.hex()}")

        # Assert that the results match
        self.assertEqual(result_x, expected_output, "Mismatch between X25519 and PyNaCl for max scalar")

    def test_scalar_multiply_large_scalars(self):
        """Test scalar multiplication with large scalar values and validate with PyNaCl."""
        large_scalar = (1 << 253) - 123456
        large_scalar_bytes = large_scalar.to_bytes(32, 'little')
        base_point = b'\x09' + b'\x00' * 31  # u-coordinate of the base point
        
        # X25519 implementation
        result_x = self.x25519_ladder.scalar_multiply(large_scalar_bytes, base_point)
        
        # Use PyNaCl for reference
        expected_output = crypto_scalarmult(large_scalar_bytes, base_point)
        
        print(f"Result from X25519: {result_x.hex()}")
        print(f"Expected (PyNaCl): {expected_output.hex()}")

        # Assert that the result matches PyNaCl's output
        self.assertEqual(result_x, expected_output, "Mismatch with PyNaCl result for large scalar")

    def test_performance(self):
        """Test the performance of MontgomeryLadder with a mid-range scalar."""
        scalar = (1 << 200) + 12345
        scalar_bytes = scalar.to_bytes(32, 'little')
        public_key = self.x25519_ladder.generate_public_key(b'\x09' + b'\x00' * 31)
        
        start_time = time.time()
        result = self.x25519_ladder.scalar_multiply(scalar_bytes, public_key)
        duration = time.time() - start_time
        print(f"Scalar multiplication took {duration:.6f} seconds.")
        self.assertTrue(isinstance(result, bytes))


if __name__ == "__main__":
    unittest.main()
