from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import json

# Function to pad the message to be a multiple of 16 bytes (AES block size)
def pad_message(message):
    padding_length = 16 - (len(message) % 16)
    padding = bytes([padding_length] * padding_length)
    return message + padding

# Function to remove the padding from a decrypted message
def unpad_message(padded_message):
    padding_length = padded_message[-1]
    return padded_message[:-padding_length]

# Function to encrypt a message using AES with the provided key
def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_ECB)
    padded_message = pad_message(message.encode())
    encrypted_message = cipher.encrypt(padded_message)
    return encrypted_message

# Function to decrypt a message using AES with the provided key
def decrypt_message(encrypted_message, key):
    cipher = AES.new(key, AES.MODE_ECB)
    padded_message = cipher.decrypt(encrypted_message)
    message = unpad_message(padded_message).decode()
    return message

# Generate a random AES key
aes_key = get_random_bytes(16)


# Secure message to be sent
secure_message = "This is a secret message."

# Encrypt the message using the AES key
encrypted_message = encrypt_message(secure_message, aes_key)

# Decrypt the encrypted message using the AES key
decrypted_message = decrypt_message(encrypted_message, aes_key)

print("Original message:", secure_message)
print("Encrypted message:", encrypted_message)
print("Decrypted message:", decrypted_message)
