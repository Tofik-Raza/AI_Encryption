import numpy as np
import tensorflow as tf
from tensorflow.keras.models import load_model
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode

# Initialize FastAPI app
app = FastAPI()

def encrypt_message(message, key):
    # Ensure the key is 32 bytes for AES-256
    key_padded = key.ljust(32)[:32].encode('utf-8')
    
    # Generate a random IV (Initialization Vector)
    iv = get_random_bytes(16)
    
    # Create AES cipher in CFB mode
    cipher = AES.new(key_padded, AES.MODE_CFB, iv)
    
    # Encrypt the message
    encrypted = cipher.encrypt(message.encode('utf-8'))
    
    # Concatenate IV and encrypted message and encode to Base64
    encrypted_message = b64encode(iv + encrypted).decode('utf-8')
    return encrypted_message

def decrypt_message(encrypted_message, key):
    try:
        # Ensure the key is 32 bytes for AES-256
        key_padded = key.ljust(32)[:32].encode('utf-8')
        
        # Decode the Base64 message
        encrypted_data = b64decode(encrypted_message)
        
        # Extract IV and ciphertext
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        
        # Create AES cipher in CFB mode
        cipher = AES.new(key_padded, AES.MODE_CFB, iv)
        
        # Decrypt the message
        decrypted = cipher.decrypt(ciphertext).decode('utf-8')
        return decrypted
    except Exception as e:
        print("Decryption error:", e)
        return "Decryption failed"
# Helper functions
def string_to_binary(string):
    binary = ''.join(format(ord(char), '08b') for char in string)
    binary_array = np.array([int(bit) for bit in binary])
    return binary_array

def binary_to_string(binary_array):
    binary_string = ''.join(str(bit) for bit in binary_array)
    chars = [chr(int(binary_string[i:i + 8], 2)) for i in range(0, len(binary_string), 8)]
    return ''.join(chars)

# Encrypt function
def encrypt_variable_length(plaintext, key, model, chunk_size):
    plaintext_binary = string_to_binary(plaintext)
    key_binary = string_to_binary(key)
    key_binary = np.tile(key_binary, len(plaintext_binary) // len(key_binary) + 1)[:len(plaintext_binary)]
    chunks = [plaintext_binary[i:i + chunk_size] for i in range(0, len(plaintext_binary), chunk_size)]
    key_chunks = [key_binary[i:i + chunk_size] for i in range(0, len(key_binary), chunk_size)]
    ciphertext_chunks = []
    for p_chunk, k_chunk in zip(chunks, key_chunks):
        p_chunk = np.pad(p_chunk, (0, chunk_size - len(p_chunk)), 'constant')
        k_chunk = np.pad(k_chunk, (0, chunk_size - len(k_chunk)), 'constant')
        input_data = np.concatenate([p_chunk, k_chunk])[np.newaxis, :]
        ciphertext_chunks.append((model.predict(input_data) > 0.5).astype(int).flatten())
    return np.concatenate(ciphertext_chunks)

# Decrypt function
def decrypt_variable_length(ciphertext, key, model, chunk_size):
    key_binary = string_to_binary(key)
    key_binary = np.tile(key_binary, len(ciphertext) // len(key_binary) + 1)[:len(ciphertext)]
    chunks = [ciphertext[i:i + chunk_size] for i in range(0, len(ciphertext), chunk_size)]
    key_chunks = [key_binary[i:i + chunk_size] for i in range(0, len(key_binary), chunk_size)]
    plaintext_chunks = []
    for c_chunk, k_chunk in zip(chunks, key_chunks):
        c_chunk = np.pad(c_chunk, (0, chunk_size - len(c_chunk)), 'constant')
        k_chunk = np.pad(k_chunk, (0, chunk_size - len(k_chunk)), 'constant')
        input_data = np.concatenate([c_chunk, k_chunk])[np.newaxis, :]
        plaintext_chunks.append((model.predict(input_data) > 0.5).astype(int).flatten())
    return np.concatenate(plaintext_chunks)

# Load saved model
chunk_size = 32  # Use the same chunk size as during training
encryption_model = load_model("encryption_model.keras")
decryption_model = load_model("decryption_model.keras")

# Pydantic model for request/response validation
class EncryptionRequest(BaseModel):
    plaintext: str
    key: str

class DecryptionRequest(BaseModel):
    ciphertext: List[int]
    key: str

# FastAPI Routes
@app.post("/encrypt/")
async def encrypt(request: EncryptionRequest):
    try:
        plaintext = request.plaintext
        key = request.key
        plaintext = encrypt_message(plaintext,key)
        ciphertext_binary = encrypt_variable_length(plaintext,key, encryption_model, chunk_size)
        return {"ciphertext": ciphertext_binary.tolist()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/decrypt/")
async def decrypt(request: DecryptionRequest):
    try:
        key = request.key
        ciphertext_binary = np.array(request.ciphertext)
        decrypted_binary = decrypt_variable_length(ciphertext_binary,key, decryption_model, chunk_size)
        decrypted_text = binary_to_string(decrypted_binary)
        decrypted_text = decrypt_message(decrypted_text,key)
        return {"decrypted_text": decrypted_text}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

