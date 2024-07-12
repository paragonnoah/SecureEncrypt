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
jpake_server = JPAKE(password, params=params)

# Start the server
HOST = '127.0.0.4'
PORT = 65431
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
    server_socket.bind((HOST, PORT))
    server_socket.listen()

    print(f"Server listening on {HOST}:{PORT}")

    while True:
        conn, addr = server_socket.accept()
        print("Connected by", addr)

        with conn:
            try:
                # Receive initial message from client
                data = conn.recv(1024)
                if not data:
                    raise ConnectionError("No data received from the client")
                else:
                    try:
                        message = json.loads(data.decode())
                        jpake_server.process_initial_message(message)
                    except json.JSONDecodeError:
                        raise ValueError("Invalid data received from the client")

                # Create and send round one message
                round_one_message = jpake_server.create_round_one_message()
                round_one_message_serializable = {
                    "gx": binascii.hexlify(int.to_bytes(round_one_message["gx"], (round_one_message["gx"].bit_length() + 7) // 8, byteorder='big')).decode(),
                    "zkp": {
                        "gr": binascii.hexlify(int.to_bytes(round_one_message["zkp"]["gr"], (round_one_message["zkp"]["gr"].bit_length() + 7) // 8, byteorder='big')).decode(),
                        "b": round_one_message["zkp"]["b"],
                        "id": binascii.hexlify(round_one_message["zkp"]["id"]).decode()
                    }
                }
                conn.sendall(json.dumps(round_one_message_serializable).encode())

                # Receive round two message from client
                data = conn.recv(1024)
                if not data:
                    raise ConnectionError("No data received from the client")
                else:
                    try:
                        message = json.loads(data.decode())
                        jpake_server.process_round_two_message(message)
                    except json.JSONDecodeError:
                        raise ValueError("Invalid data received from the client")

                # Ensure message["gx"] is an integer
                message_gx = int(message["gx"], 16)

                # Encrypt and send response message
                secure_message = "This is a secret message."
                shared_secret = jpake_server.generate_shared_secret(message_gx)
                cipher = AES.new(int.to_bytes(shared_secret, 16, byteorder='big'), AES.MODE_ECB)
                padded_message = secure_message.encode() + b"\0" * (16 - len(secure_message) % 16)
                encrypted_message = cipher.encrypt(padded_message)
                encoded_encrypted_message = base64.b64encode(encrypted_message).decode()
                conn.sendall(json.dumps({"message": encoded_encrypted_message}).encode())

                print("Sent:", secure_message)

            except Exception as e:
                print("Error:", e)
