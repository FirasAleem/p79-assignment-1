from nacl.bindings import crypto_scalarmult

private_key = b'\x00' * 32
public_key = b'\x09' + b'\x00' * 31
result = crypto_scalarmult(private_key, public_key)
print(f"Expected result for scalar 0: {result.hex()}")
