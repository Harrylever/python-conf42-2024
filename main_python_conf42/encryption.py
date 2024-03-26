from cryptography.fernet import Fernet

cipher_key = Fernet.generate_key()
cipher_suite = Fernet(key=cipher_key)

inputted_message = input('Enter message to encrypt? ')
bytes_message = inputted_message

# Encrypt our message
# message = b'This is confidential text from the NSA'
encrypted_message = cipher_suite.encrypt(bytes_message)

# Decrypt our message
decrypted_message = cipher_suite.decrypt(encrypted_message)

print(f"Original message: {message}")
print(f"Encrypted message: {encrypted_message}")
print(f"Decrypted message: {decrypted_message.decode()}")