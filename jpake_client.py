import socket
import json
import binascii
import base64
from jpake_protocol import JPAKE, JPAKEParams
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Shared parameters
params = JPAKEParams(p=23, q=11, g=2)
password = "shared_password"

# Initialize JPAKE with shared password
jpake_client = JPAKE(password, params=params)

# Connect to the server
HOST = '127.0.0.4'
PORT = 65431
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    try:
        s.connect((HOST, PORT))
        print("Connected to server")

        # Perform round one of J-PAKE handshake
        message = jpake_client.create_initial_message()
        # Convert bytes to hexadecimal string
        message_serializable = {
            "gx": binascii.hexlify(int.to_bytes(message["gx"], (message["gx"].bit_length() + 7) // 8, byteorder='big')).decode(),
            "zkp": {
                "gr": binascii.hexlify(int.to_bytes(message["zkp"]["gr"], (message["zkp"]["gr"].bit_length() + 7) // 8, byteorder='big')).decode(),
                "b": message["zkp"]["b"],
                "id": binascii.hexlify(message["zkp"]["id"]).decode()
            }
        }
        s.sendall(json.dumps(message_serializable).encode())
        print("Round one completed")

        # Receive round one message from server
        data = s.recv(1024)
        if not data:
            raise ConnectionError("No data received from the server")
        else:
            try:
                message = json.loads(data.decode())
                jpake_client.process_round_one_message(message)
            except json.JSONDecodeError:
                raise ValueError("Invalid data received from the server")

        # Create round two message
        round_two_message = jpake_client.create_round_two_message()
        # Convert bytes to hexadecimal string
        round_two_message_serializable = {
            "gx": binascii.hexlify(int.to_bytes(round_two_message["gx"], (round_two_message["gx"].bit_length() + 7) // 8, byteorder='big')).decode(),
            "zkp": {
                "gr": binascii.hexlify(int.to_bytes(round_two_message["zkp"]["gr"], (round_two_message["zkp"]["gr"].bit_length() + 7) // 8, byteorder='big')).decode(),
                "b": round_two_message["zkp"]["b"],
                "id": binascii.hexlify(round_two_message["zkp"]["id"]).decode()
            }
        }
        s.sendall(json.dumps(round_two_message_serializable).encode())
        print("Round two completed")

        # Receive encrypted message from server
        data = s.recv(1024)
        if not data:
            raise ConnectionError("No data received from the server")
        else:
            encrypted_response = json.loads(data.decode()).get("message")
            if encrypted_response is None:
                raise ValueError("Invalid data received from the server")

        # Decrypt the message using the shared secret
        shared_secret = jpake_client.generate_shared_secret(round_two_message["gx"])  # Calculate shared secret
        cipher = AES.new(int.to_bytes(shared_secret, 16, byteorder='big'), AES.MODE_ECB)
        decoded_encrypted_response = base64.b64decode(encrypted_response)
        decrypted_response = cipher.decrypt(decoded_encrypted_response).rstrip(b'\0').decode()  # Decrypt message
        print("Received:", decrypted_response)

    except Exception as e:
        print("Error:", e)
