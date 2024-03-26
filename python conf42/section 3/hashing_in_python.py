import hashlib
import bcrypt
import random

data = b"Password123_4#"

# Hashing with SHA-256
# sha256_hash = hashlib.sha256(data).hexdigest()

# Hashing with SHA-256 including salt
# salt = str(random.getrandbits(256))
# sha256_hash_with_salt = hashlib.sha256(data + bytes(salt, 'utf-8')).hexdigest()

# Hashing with bcrypt (this better for passwords!)
bcrypt_hash = bcrypt.hashpw(data, bcrypt.gensalt())

# print(f"SHA-256 hash: {sha256_hash}\n")
# print(f"SHA-256 hash with salt: {sha256_hash_with_salt}\n")
# print(f"bcrypt hash: {bcrypt_hash}")

print("")

if __name__ == "__main__":
    user_enter_password = input("Enter your password: ")

    # compare hash
    bcrypt_hash_compare_is_valid = bcrypt.checkpw(
        bytes(user_enter_password, 'utf-8'), bcrypt_hash)

    if bcrypt_hash_compare_is_valid is True:
        print(f"Login successful!")
    else:
        print(f"Wrong password or email")
