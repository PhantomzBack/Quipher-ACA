#!/usr/bin/env python3
"""
Cryptography Assignment - Client Script
=======================================
This client connects to the crypto server and demonstrates symmetric key cryptography.
Students should implement the encrypt() and decrypt() functions.
Uses length-prefixed messages for reliable socket communication.

The client:
1. Encrypts messages before sending them to the server
2. Decrypts messages received from other clients via the server
"""

import socket
import threading
import json
import sys

class CryptoClient:
    def __init__(self, host='localhost', port=12345):
        self.host = host
        self.port = port
        self.socket = None
        self.username = ""
        self.encryption_key = ""
        self.running = False
        
    def send_message_to_server(self, message):
        """Send a message with length prefix for reliable transmission"""
        try:
            message_bytes = message.encode('utf-8')
            message_length = len(message_bytes)
            # Send 4-byte length prefix followed by the message
            self.socket.send(message_length.to_bytes(4, byteorder='big'))
            self.socket.send(message_bytes)
        except Exception as e:
            raise e
    
    def receive_message_from_server(self):
        """Receive a message with length prefix"""
        try:
            # First receive the 4-byte length prefix
            length_bytes = b''
            while len(length_bytes) < 4:
                chunk = self.socket.recv(4 - len(length_bytes))
                if not chunk:
                    return None
                length_bytes += chunk
            
            message_length = int.from_bytes(length_bytes, byteorder='big')
            
            # Now receive the actual message
            message_bytes = b''
            while len(message_bytes) < message_length:
                chunk = self.socket.recv(message_length - len(message_bytes))
                if not chunk:
                    return None
                message_bytes += chunk
            
            return message_bytes.decode('utf-8')
        except Exception as e:
            return None
        
    def encrypt(self, message, key):
        """
        STUDENT TASK: Implement symmetric encryption here
        
        Args:
            message (str): The plaintext message to encrypt
            key (str): The encryption key
            
        Returns:
            str: The encrypted message
            
        Hint: You can use Caesar cipher, XOR, or any symmetric encryption method
        Example: For Caesar cipher, shift each letter by a value derived from the key
        """
        # TODO: Students need to implement this function
        # For now, returning the message as-is (no encryption)
        print(f"[CLIENT-ENCRYPT] Message: '{message}' with key: '{key}'")
        return message  # Replace this with actual encryption
        
    def decrypt(self, encrypted_message, key):
        """
        STUDENT TASK: Implement symmetric decryption here
        
        Args:
            encrypted_message (str): The encrypted message to decrypt
            key (str): The decryption key
            
        Returns:
            str: The decrypted plaintext message
            
        Hint: This should reverse the encryption process exactly
        If you used Caesar cipher for encryption, reverse the shift here
        """
        # TODO: Students need to implement this function
        # For now, returning the message as-is (no decryption)
        print(f"[CLIENT-DECRYPT] Encrypted: '{encrypted_message}' with key: '{key}'")
        return encrypted_message  # Replace this with actual decryption
        
    def receive_messages(self):
        """Handle incoming messages from the server"""
        while self.running:
            try:
                data = self.receive_message_from_server()
                if not data:
                    break
                    
                message_data = json.loads(data)
                
                if message_data['type'] == 'welcome':
                    print(f"\n🎉 {message_data['message']}")
                    self.encryption_key = message_data['key']
                    print(f"🔑 Encryption key received: {self.encryption_key}")
                    print(f"ℹ️  {message_data['server_info']}")
                    print("-" * 50)
                    
                elif message_data['type'] == 'message':
                    timestamp = message_data['timestamp']
                    username = message_data['username']
                    encrypted_message = message_data['message']
                    
                    # Decrypt the received message from another client
                    decrypted_message = self.decrypt(encrypted_message, self.encryption_key)
                    print(f"\n[{timestamp}] {username}: {decrypted_message}")
                    print(f"📥 (Received encrypted: {encrypted_message})")
                    
                elif message_data['type'] == 'user_update':
                    action = message_data['action']
                    username = message_data['username']
                    user_count = message_data['user_count']
                    online_users = message_data['online_users']
                    
                    if action == 'joined':
                        print(f"\n✅ {username} joined the chat")
                    elif action == 'left':
                        print(f"\n❌ {username} left the chat")
                        
                    print(f"👥 Online users ({user_count}): {', '.join(online_users)}")
                    
            except json.JSONDecodeError:
                print("[ERROR] Received invalid data from server")
                break
            except Exception as e:
                if self.running:
                    print(f"[ERROR] Connection error: {e}")
                break
                
    def send_message(self, message):
        """Send an encrypted message to the server"""
        try:
            # Encrypt the message before sending
            encrypted_message = self.encrypt(message, self.encryption_key)
            
            message_data = {
                'type': 'message',
                'message': encrypted_message
            }
            
            self.send_message_to_server(json.dumps(message_data))
            print(f"📤 Message sent (encrypted): {encrypted_message}")
            
        except Exception as e:
            print(f"[ERROR] Failed to send message: {e}")
            
    def connect_to_server(self):
        """Connect to the crypto server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            
            # Send username to server
            username_data = {'username': self.username}
            self.send_message_to_server(json.dumps(username_data))
            
            self.running = True
            
            # Start receiving thread
            receive_thread = threading.Thread(target=self.receive_messages)
            receive_thread.daemon = True
            receive_thread.start()
            
            return True
            
        except Exception as e:
            print(f"[ERROR] Failed to connect to server: {e}")
            return False
            
    def disconnect(self):
        """Disconnect from the server"""
        self.running = False
        if self.socket:
            self.socket.close()
        print("\n👋 Disconnected from server")
        
    def start_chat(self):
        """Start the chat interface"""
        print("\n=== Crypto Chat Started ===")
        print("Type your messages and press Enter to send")
        print("Type 'quit' or 'exit' to leave the chat")
        print("Type 'help' for commands")
        print("-" * 40)
        
        while self.running:
            try:
                message = input("\n💬 Enter message: ").strip()
                
                if not message:
                    continue
                    
                if message.lower() in ['quit', 'exit', 'q']:
                    print("Goodbye! 👋")
                    break
                    
                elif message.lower() == 'help':
                    self.show_help()
                    continue
                    
                elif message.lower() == 'key':
                    print(f"🔑 Current encryption key: {self.encryption_key}")
                    continue
                    
                elif message.lower() == 'test':
                    self.test_encryption()
                    continue
                    
                # Send the message (will be encrypted automatically)
                self.send_message(message)
                
            except KeyboardInterrupt:
                print("\n\nReceived interrupt signal...")
                break
            except Exception as e:
                print(f"[ERROR] Error in chat: {e}")
                break
                
        self.disconnect()
        
    def show_help(self):
        """Show available commands"""
        print("\n=== Available Commands ===")
        print("help    - Show this help message")
        print("key     - Show current encryption key")
        print("test    - Test encryption/decryption functions")
        print("quit    - Exit the chat")
        print("========================")
        
    def test_encryption(self):
        """Test the encryption and decryption functions"""
        ## TODO: Implement a simple test for encryption/decryption 

def main():
    """Main function to run the crypto client"""
    print("=== Cryptography Assignment - Client ===")
    print("Students: Implement the encrypt() and decrypt() functions!")
    print("Uses length-prefixed messages for reliable socket communication")
    print("The client encrypts outgoing messages and decrypts incoming messages.")
    print()
    
    # Get username
    while True:
        username = input("Enter your username: ").strip()
        if username and len(username) >= 2:
            break
        print("Username must be at least 2 characters long!")
    
    # Get server details (optional)
    host = input("Enter server host (press Enter for localhost): ").strip()
    if not host:
        host = 'localhost'
        
    port_input = input("Enter server port (press Enter for 12345): ").strip()
    try:
        port = int(port_input) if port_input else 12345
    except ValueError:
        port = 12345
    
    # Create and connect client
    client = CryptoClient(host, port)
    client.username = username
    
    print(f"\nConnecting to {host}:{port} as '{username}'...")
    
    if client.connect_to_server():
        print("✅ Connected successfully!")
        try:
            client.start_chat()
        except KeyboardInterrupt:
            print("\n\nShutting down...")
            client.disconnect()
    else:
        print("❌ Failed to connect to server")
        print("Make sure the server is running and accessible")

if __name__ == "__main__":
    main()
