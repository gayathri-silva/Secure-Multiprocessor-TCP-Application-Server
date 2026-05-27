import socket
import sys

HOST = '127.0.0.1'
PORT = 50626
current_token = None

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    sock.connect((HOST, PORT))
    print(f"Connected to server on port {PORT}")
except Exception as e:
    print("Cannot connect:", e)
    sys.exit(1)

while True:
    try:
        cmd = input("\nEnter command (or 'quit'): ").strip()
        if cmd.lower() == 'quit':
            break

        # Automatically add token for protected commands
        if current_token and not cmd.upper().startswith(('REGISTER', 'LOGIN')):
            full_payload = cmd + " " + current_token
        else:
            full_payload = cmd

        n = len(full_payload)
        message = f"LEN:{n} {full_payload}"
        sock.sendall(message.encode('utf-8'))

        response = sock.recv(4096).decode('utf-8').strip()
        print("Server:", response)

        # Extract token after successful LOGIN
        if cmd.upper().startswith('LOGIN') and response.startswith('OK') and 'token:' in response:
            current_token = response.split('token:')[1].split()[0]
            print(f"Token saved: {current_token}")

    except Exception as e:
        print("Error:", e)
        break

sock.close()
