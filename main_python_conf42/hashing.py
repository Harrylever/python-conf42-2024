import hashlib
import bcrypt
import random

data = b"This is data from my Father"

# Hash with SHA256
sha256_hash = hashlib.sha256(data).hexdigest()

# Hash with SHA256 with salt
salt = str(random.getrandbits(256))
sha256_hash_with_salt = hashlib.sha256(data + bytes(salt, 'utf-8')).hexdigest()

# Hash with bcrypt (this better for password)
brcypt_hash = bcrypt.hashpw(data, bcrypt.gensalt())

print(f'SHA256 HASH: {sha256_hash}\n')
print(f'SHA256 HASH WITH SALT: {sha256_hash_with_salt}\n')
print(f'BCRYPT HASH: {brcypt_hash}\n')