#!/usr/bin/env python3
"""
Cryptography Assignment - Server Script
========================================
This server manages multiple client connections and relays encrypted messages.
The server does NOT handle encryption/decryption - that's done by the clients.
Uses length-prefixed messages for reliable socket communication.
"""

import socket
import threading
import json
import time
from datetime import datetime

class CryptoServer:
    def __init__(self, host='localhost', port=12345):
        self.host = host
        self.port = port
        self.clients = {}  # {socket: {'username': str, 'address': tuple}}
        self.current_key = "ASSIGNMENT_KEY_2025"  # Simple key for demonstration
        self.server_socket = None
        self.running = False
        
    # Note: Server does not handle encryption/decryption
    # All encryption/decryption is handled by the clients
    # Server just relays encrypted messages between clients
    
    def send_message(self, client_socket, message):
        """Send a message with length prefix for reliable transmission"""
        try:
            message_bytes = message.encode('utf-8')
            message_length = len(message_bytes)
            # Send 4-byte length prefix followed by the message
            client_socket.send(message_length.to_bytes(4, byteorder='big'))
            client_socket.send(message_bytes)
        except Exception as e:
            raise e
    
    def receive_message(self, client_socket):
        """Receive a message with length prefix"""
        try:
            # First receive the 4-byte length prefix
            length_bytes = b''
            while len(length_bytes) < 4:
                chunk = client_socket.recv(4 - len(length_bytes))
                if not chunk:
                    return None
                length_bytes += chunk
            
            message_length = int.from_bytes(length_bytes, byteorder='big')
            
            # Now receive the actual message
            message_bytes = b''
            while len(message_bytes) < message_length:
                chunk = client_socket.recv(message_length - len(message_bytes))
                if not chunk:
                    return None
                message_bytes += chunk
            
            return message_bytes.decode('utf-8')
        except Exception as e:
            return None
        
    def broadcast_message(self, sender_socket, encrypted_message):
        """Broadcast an encrypted message to all connected clients except the sender"""
        sender_username = self.clients[sender_socket]['username']
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Note: Server relays the encrypted message as-is
        # Clients will decrypt it themselves
        print(f"[RELAY] Relaying encrypted message from {sender_username}: {encrypted_message}")
        
        broadcast_data = {
            'type': 'message',
            'username': sender_username,
            'message': encrypted_message,  # Send encrypted message as-is
            'timestamp': timestamp
        }
        
        # Send to all clients except sender using length-prefixed messages
        disconnected_clients = []
        for client_socket in self.clients:
            if client_socket != sender_socket:
                try:
                    self.send_message(client_socket, json.dumps(broadcast_data))
                except:
                    disconnected_clients.append(client_socket)
        
        # Clean up disconnected clients
        for client in disconnected_clients:
            self.remove_client(client)
            
    def broadcast_user_update(self, message_type, username):
        """Notify all clients about user connections/disconnections"""
        user_list = [client_info['username'] for client_info in self.clients.values()]
        
        update_data = {
            'type': 'user_update',
            'action': message_type,  # 'joined' or 'left'
            'username': username,
            'online_users': user_list,
            'user_count': len(user_list)
        }
        
        disconnected_clients = []
        for client_socket in self.clients:
            try:
                self.send_message(client_socket, json.dumps(update_data))
            except:
                disconnected_clients.append(client_socket)
                
        # Clean up disconnected clients
        for client in disconnected_clients:
            self.remove_client(client)
            
    def handle_client(self, client_socket, client_address):
        """Handle individual client connections"""
        try:
            # Receive username using length-prefixed message
            username_data = self.receive_message(client_socket)
            if not username_data:
                return
            username = json.loads(username_data)['username']
            
            # Store client info
            self.clients[client_socket] = {
                'username': username,
                'address': client_address
            }
            
            print(f"[CONNECTION] {username} connected from {client_address}")
            
            # Send welcome message with current key
            welcome_data = {
                'type': 'welcome',
                'message': f'Welcome to the Crypto Chat, {username}!',
                'key': self.current_key,
                'server_info': 'Server relays encrypted messages - clients handle encryption/decryption'
            }
            self.send_message(client_socket, json.dumps(welcome_data))
            
            # Notify all clients about new user
            self.broadcast_user_update('joined', username)
            
            # Handle messages from this client
            while self.running:
                try:
                    data = self.receive_message(client_socket)
                    if not data:
                        break
                        
                    message_data = json.loads(data)
                    
                    if message_data['type'] == 'message':
                        encrypted_message = message_data['message']
                        print(f"[RECEIVED] Encrypted message from {username}: {encrypted_message}")
                        # Relay the encrypted message to other clients
                        self.broadcast_message(client_socket, encrypted_message)
                        
                except json.JSONDecodeError:
                    print(f"[ERROR] Invalid JSON from {username}")
                    break
                except Exception as e:
                    print(f"[ERROR] Error handling client {username}: {e}")
                    break
                    
        except Exception as e:
            print(f"[ERROR] Error with client {client_address}: {e}")
        finally:
            self.remove_client(client_socket)
            
    def remove_client(self, client_socket):
        """Remove a client from the server"""
        if client_socket in self.clients:
            username = self.clients[client_socket]['username']
            del self.clients[client_socket]
            client_socket.close()
            print(f"[DISCONNECTION] {username} disconnected")
            
            # Notify remaining clients
            if self.clients:  # Only if there are still clients connected
                self.broadcast_user_update('left', username)
                
    def start_server(self):
        """Start the crypto server"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True
            
            print(f"[SERVER] Crypto Server started on {self.host}:{self.port}")
            print(f"[SERVER] Encryption key for clients: {self.current_key}")
            print(f"[SERVER] Using length-prefixed messages for reliable communication")
            print(f"[SERVER] Server relays encrypted messages (no server-side encryption)")
            print(f"[SERVER] Waiting for client connections...")
            print("-" * 60)
            
            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, client_address)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    
                except OSError:
                    if self.running:
                        print("[ERROR] Server socket error")
                    break
                    
        except Exception as e:
            print(f"[ERROR] Failed to start server: {e}")
        finally:
            self.stop_server()
            
    def stop_server(self):
        """Stop the crypto server"""
        print("\n[SERVER] Shutting down...")
        self.running = False
        
        # Close all client connections
        for client_socket in list(self.clients.keys()):
            self.remove_client(client_socket)
            
        # Close server socket
        if self.server_socket:
            self.server_socket.close()
            
        print("[SERVER] Server stopped")

def main():
    """Main function to run the crypto server"""
    print("=== Cryptography Assignment - Server ===")
    print("Server relays encrypted messages between clients")
    print("Uses length-prefixed messages for reliable socket communication")
    print("Students: Implement encrypt() and decrypt() functions in the CLIENT!")
    print()
    
    server = CryptoServer()
    
    try:
        server.start_server()
    except KeyboardInterrupt:
        print("\n[SERVER] Received shutdown signal")
        server.stop_server()

if __name__ == "__main__":
    main()