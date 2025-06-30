# Cryptography Assignment - Symmetric Key Encryption

## Overview
This assignment demonstrates symmetric key cryptography using Python socket programming. Students will implement encryption and decryption functions to enable secure communication between multiple clients through a central server.

## Assignment Structure

### Files Included:
1. **crypto_server.py** - The server that manages client connections and message broadcasting
2. **crypto_client.py** - The client script that students use to connect and chat
3. **README.md** - This instruction file

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

### Step 2: Implement the Test Functionality
- Implement the `test_encryption` functionality to help test your functions/

### Step 3: Implement Encryption Functions
You need to implement the following functions in **BOTH** files:

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

## Getting Help
- Use the `help` command in the client for available commands
- Use the `test` command to verify your encryption functions
- Check server logs for debugging information
- Review the example solutions for inspiration (after attempting yourself)

---
**Note:** This assignment focuses on learning cryptographic concepts. The implementations here are for educational purposes and should not be used for actual secure communications in production systems.
