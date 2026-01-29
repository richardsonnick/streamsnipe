import socket
import ssl
import threading
import os
from subprocess import run

# --- 1. Setup: Generate a temporary self-signed certificate ---
# We need this for the TLS server to function.
def generate_cert():
    if not os.path.exists("server.pem"):
        print("Generating self-signed certificate...")
        cmd = [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", 
            "-keyout", "server.pem", "-out", "server.pem", 
            "-days", "1", "-nodes", "-subj", "/CN=localhost"
        ]
        run(cmd, check=True)

# --- 2. The TLS Server ---
def start_server():
    # In your server context:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.maximum_version = ssl.TLSVersion.TLSv1_2  # Force 1.2
    context.load_cert_chain(certfile="server.pem")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('127.0.0.1', 8443))
        sock.listen(5)
        print("Server: Listening on 8443...")
        
        # Wait for one connection then exit
        conn, addr = sock.accept()
        with context.wrap_socket(conn, server_side=True) as ssock:
            print(f"Server: Established {ssock.version()} connection with {addr}")
            ssock.sendall(b"Hello from the server!")

# --- 3. The TLS Client ---
def start_client():
    # We tell the client to ignore cert validation since it's self-signed
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    print("Client: Connecting to server...")
    with socket.create_connection(('127.0.0.1', 8443)) as sock:
        with context.wrap_socket(sock, server_hostname='localhost') as ssock:
            print(f"Client: Handshake complete. Using {ssock.cipher()}")
            data = ssock.recv(1024)
            print(f"Client: Received: {data.decode()}")

# --- 4. Execution ---
if __name__ == "__main__":
    generate_cert()

    # Start server in a background thread
    server_thread = threading.Thread(target=start_server)
    server_thread.start()

    # Give the server a moment to bind to the port
    import time
    time.sleep(1)

    # Run the client in the main thread
    try:
        start_client()
    finally:
        server_thread.join()
        # Cleanup
        if os.path.exists("server.pem"):
            os.remove("server.pem")
