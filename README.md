# Cryptography Assignment - Symmetric Key Encryption

## Overview
This assignment demonstrates symmetric key cryptography using Python socket programming. Students will implement encryption and decryption functions to enable secure communication between multiple clients through a central server.

## Assignment Structure

### Files Included:
1. **crypto_server.py** - The server that manages client connections and message broadcasting
2. **crypto_client.py** - The client script that students use to connect and chat
3. **README.md** - This instruction file
4. **example_solutions.py** - Example encryption implementations (for instructor reference)

## Learning Objectives
- Understand symmetric key cryptography concepts
- Implement basic encryption/decryption algorithms
- Learn about socket programming and client-server communication
- Experience real-time encrypted messaging

## Your Task

### Step 1: Understand the Code Structure
- Review both `crypto_server.py` and `crypto_client.py`
- Identify where the `encrypt()` and `decrypt()` functions are called
- Notice that currently, messages are sent without actual encryption

### Step 2: Implement Encryption Functions
You need to implement the following functions in **BOTH** files:

#### In crypto_server.py:
```python
def encrypt(self, message, key):
    # Your encryption implementation here
    pass

def decrypt(self, encrypted_message, key):
    # Your decryption implementation here
    pass
```

#### In crypto_client.py:
```python
def encrypt(self, message, key):
    # Your encryption implementation here (same as server)
    pass

def decrypt(self, encrypted_message, key):
    # Your decryption implementation here (same as server)
    pass
```

### Step 3: Test Your Implementation
1. Start the server: `python crypto_server.py`
2. Start multiple clients: `python crypto_client.py`
3. Send messages between clients
4. Verify that messages are encrypted during transmission but readable when received

## Encryption Algorithm Suggestions

### Beginner Level: Caesar Cipher
- Shift each character by a fixed amount
- Use the key to determine the shift value

### Intermediate Level: XOR Cipher
- XOR each character with the key
- Repeat the key if it's shorter than the message

### Advanced Level: Vigenère Cipher
- Use a repeating key to shift characters
- More secure than Caesar cipher

## Requirements
- The same key must work for both encryption and decryption
- Messages must be encrypted before transmission
- Messages must be decrypted correctly when received
- The implementation should be identical in both server and client

## Testing Your Solution
1. Use the built-in `test` command in the client to verify your functions work
2. Send messages between multiple clients
3. Check server logs to see encrypted messages in transit

## Bonus Challenges
1. Implement multiple encryption algorithms and let users choose
2. Add key rotation (change keys periodically)
3. Implement a more sophisticated encryption algorithm
4. Add message integrity checking (hash functions)

## Common Pitfalls
- Make sure encryption and decryption are exact inverses
- Handle edge cases (empty messages, special characters)
- Ensure the same algorithm is used in both client and server
- Test with various message lengths and content types

## Submission Guidelines
Submit your modified `crypto_server.py` and `crypto_client.py` files with your encryption implementations. Include a brief explanation of your chosen algorithm and any design decisions.

## Grading Criteria
- Correctness of encryption/decryption implementation (40%)
- Code quality and documentation (20%)
- Proper handling of edge cases (20%)
- Testing and verification (20%)

## Getting Help
- Use the `help` command in the client for available commands
- Use the `test` command to verify your encryption functions
- Check server logs for debugging information
- Review the example solutions for inspiration (after attempting yourself)

---
**Note:** This assignment focuses on learning cryptographic concepts. The implementations here are for educational purposes and should not be used for actual secure communications in production systems.
