import os
import binascii
import hashlib
import random
from Crypto.Cipher import AES

class JPAKEError(Exception):
    pass

class DuplicateSignerID(JPAKEError):
    pass

class BadZeroKnowledgeProof(JPAKEError):
    pass

class JPAKEParams:
    def __init__(self, p, q, g):
        self.p = p
        self.q = q
        self.g = g
        self.order_len = (1 + len(hex(self.p)[2:])) // 2 * 2  # bytes

class JPAKE:
    def __init__(self, password, params=None, signer_id=None):
        if params is None:
            params = JPAKEParams(p=23, q=11, g=2)
        if signer_id is None:
            signer_id = binascii.hexlify(os.urandom(16)).decode('ascii')
        self.signer_id = signer_id.encode('ascii')
        self.params = params
        self.s = self.password_to_int(password)

    def password_to_int(self, password):
        return int.from_bytes(hashlib.sha256(password.encode('utf-8')).digest(), byteorder='big') % (self.params.q - 1)

    def create_initial_message(self):
        x = random.randrange(1, self.params.q)
        gx = pow(self.params.g, x, self.params.p)
        zero_knowledge_proof = self.create_zero_knowledge_proof(self.params.g, x, gx)
        return {"gx": gx, "zkp": zero_knowledge_proof}

    def process_initial_message(self, message):
        gx = message["gx"]
        partner_proof = message["zkp"]
        self.verify_zero_knowledge_proof(partner_proof, gx)

    def create_round_one_message(self):
        return self._generate_round_message()

    def process_round_one_message(self, message):
        return self._process_round_message(message)

    def create_round_two_message(self):
        return self._generate_round_message()

    def process_round_two_message(self, message):
        return self._process_round_message(message)

    def _generate_round_message(self):
        gx = self.calculate_gx()
        zero_knowledge_proof = self.create_zero_knowledge_proof(self.params.g, self.s, gx)
        return {"gx": gx, "zkp": zero_knowledge_proof}

    def _process_round_message(self, message):
        gx = message["gx"]
        partner_proof = message["zkp"]
        self.verify_zero_knowledge_proof(partner_proof, gx)

    def calculate_gx(self):
        return pow(self.params.g, self.s, self.params.p)

    def create_zero_knowledge_proof(self, generator, exponent, gx):
        q = self.params.q
        p = self.params.p
        while True:
            r = random.randrange(1, q)
            gr = pow(generator, r, p)
            if pow(gr, q, p) == 1:
                break
        h = self.compute_hash(gx, gr)
        b = (r - exponent * h) % q
        return {"gr": gr, "b": b, "id": self.signer_id}

    def verify_zero_knowledge_proof(self, proof, partner_gx):
        q = self.params.q
        gr = bytes_to_int(binascii.unhexlify(proof["gr"]))  # Convert hexadecimal string to integer
        partner_gx = bytes_to_int(binascii.unhexlify(partner_gx))  # Convert hexadecimal string to integer

        if pow(gr, q, self.params.p) != 1:
            raise BadZeroKnowledgeProof("gr^q != 1 mod p")

        h = self.compute_hash(partner_gx, gr)
        computed_value = (gr * pow(self.params.g, proof["b"], self.params.p)) % self.params.p
        expected_value = (pow(partner_gx, h, self.params.p) * pow(gr, proof["b"], self.params.p)) % self.params.p

        return computed_value == expected_value


    def compute_hash(self, gx, gr):
        data = (
            int_to_bytes(gx, self.params.order_len) +
            int_to_bytes(gr, self.params.order_len) +
            int_to_bytes(len(self.signer_id), 2) +
            self.signer_id
        )
        return int.from_bytes(sha256_hash(data), byteorder='big')

    def generate_shared_secret(self, partner_gx):
        return pow(partner_gx, self.s, self.params.p)

    def encrypt_message(self, message, shared_secret):
        cipher = AES.new(int_to_bytes(shared_secret, 16), AES.MODE_ECB)
        padded_message = message.encode() + b"\0" * (16 - len(message) % 16)  # Pad the message
        encrypted_message = cipher.encrypt(padded_message)
        return base64.b64encode(encrypted_message).decode()

    def decrypt_message(self, encrypted_message, shared_secret):
        cipher = AES.new(int_to_bytes(shared_secret, 16), AES.MODE_ECB)
        decoded_encrypted_message = base64.b64decode(encrypted_message)
        decrypted_message = cipher.decrypt(decoded_encrypted_message).rstrip(b'\0').decode()  # Remove padding and decode
        return decrypted_message

def int_to_bytes(integer, length):
    return integer.to_bytes(length, byteorder='big')

def bytes_to_int(byte_string):
    return int.from_bytes(byte_string, byteorder='big')

def sha1_hash(data):
    return hashlib.sha1(data).digest()

def sha256_hash(data):
    return hashlib.sha256(data).digest()
