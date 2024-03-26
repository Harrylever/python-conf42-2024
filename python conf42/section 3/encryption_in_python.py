from cryptography.fernet import Fernet

cipher_key = Fernet.generate_key() # generate a random key
cipher_suite = Fernet(key=cipher_key)

# Encrypt a message
message = b"This is a secret message!"
encrypted_message = cipher_suite.encrypt(message);

# Decrypt the message
decrypted_message = cipher_suite.decrypt(encrypted_message)

print(f"Original message: {message}")
print(f"Encrypted message: {encrypted_message}")
print(f"Dencrypted message: {decrypted_message.decode()}")