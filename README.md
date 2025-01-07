##Encryption and Decryption API:-

This project implements a FastAPI-based service for secure encryption and decryption of text using a combination of traditional cryptographic methods (AES-256) and a custom deep learning model for variable-length encryption.

#Features:-

AES-256 Encryption: Uses AES in CFB mode for initial text encryption with a user-provided key.
Deep Learning Encryption: Processes the AES-encrypted message with a neural network to generate a binary ciphertext.
Variable-Length Support: Handles arbitrary text lengths by chunking and aligning input data.
FastAPI Integration: Provides RESTful endpoints for encryption and decryption.

#Requirements:-
Python 3.8 or higher
Required Python libraries:
numpy
tensorflow
fastapi
pydantic
uvicorn
pycryptodome

#Setup Instructions:-

1. Install Dependencies

pip install numpy tensorflow fastapi pydantic uvicorn pycryptodome

3. Load Pre-Trained Models
Place the pre-trained encryption and decryption models (encryption_model.keras and decryption_model.keras) in the project directory.

4. Run the API
Start the FastAPI server using Uvicorn:

uvicorn app:app --host 0.0.0.0 --port 8000
The API will be accessible at http://localhost:8000.

##API Endpoints:-
#1. Encrypt:-
Endpoint: /encrypt/
Method: POST

Request Body:
json:
{
  "plaintext": "Your plaintext message",
  "key": "YourSecretKey"
}

Response:
json
{
  "ciphertext": [0, 1, 1, 0, ...]  // Binary array of ciphertext
}


#2. Decrypt:-
Endpoint: /decrypt/
Method: POST

Request Body:
json
{
  "ciphertext": [0, 1, 1, 0, ...],  // Binary array of ciphertext
  "key": "YourSecretKey"
}
Response:
json
{
  "decrypted_text": "Your plaintext message"
}
#Code Structure:-
app.py: Contains the FastAPI application, encryption/decryption logic, and utility functions.
Pre-Trained Models: Neural network models for binary-level encryption and decryption (encryption_model.keras, decryption_model.keras).

#Security Notes:-
Ensure the key provided is strong and unique for secure encryption.
Models must be properly trained and validated for robust security.
Protect the API from unauthorized access by implementing authentication and HTTPS in production.

#Example Usage:-
Start the API.
Send a POST request to /encrypt/ with plaintext and key.
Use the response ciphertext to send a POST request to /decrypt/ with the same key to retrieve the original plaintext.

This service is ideal for applications requiring secure and novel encryption techniques combining traditional cryptography and AI.
