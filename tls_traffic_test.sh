#!/bin/bash
# tls_traffic_test.sh - Generate TLS traffic using various implementations

set -e

echo "=========================================="
echo "TLS Traffic Generator for BPF Probe Testing"
echo "=========================================="
echo ""
echo "Make sure your BPF probe is running in another terminal!"
echo "Press Enter to start..."
read

# Test target - use a reliable HTTPS server
TARGET="www.google.com"

echo ""
echo "=== 1. curl (OpenSSL) - TLS 1.2 ==="
echo "    To debug: strace -e read,recvfrom,recvmsg curl -s --tlsv1.2 --tls-max 1.2 https://$TARGET 2>&1 | grep '\\\\26\\\\3'"
sh -c 'echo "    PID: $$"; exec curl -s --tlsv1.2 --tls-max 1.2 -o /dev/null https://'"$TARGET"'' && echo "    curl TLS 1.2: OK" || echo "    curl TLS 1.2 failed"
echo ">>> Check probe output, then press Enter..."
read

echo ""
echo "=== 2. curl (OpenSSL) - TLS 1.3 ==="
echo "    To debug: strace -e read,recvfrom,recvmsg curl -s --tlsv1.3 https://$TARGET 2>&1 | grep '\\\\26\\\\3'"
sh -c 'echo "    PID: $$"; exec curl -s --tlsv1.3 -o /dev/null https://'"$TARGET"'' && echo "    curl TLS 1.3: OK" || echo "    curl TLS 1.3 failed"
echo ">>> Check probe output, then press Enter..."
read

echo ""
echo "=== 3. openssl s_client - TLS 1.2 ==="
echo "    To debug: echo Q | strace -e read,recvfrom,recvmsg openssl s_client -connect $TARGET:443 -tls1_2 2>&1 | grep '\\\\26\\\\3'"
sh -c 'echo "    PID: $$"; echo "Q" | exec openssl s_client -connect '"$TARGET"':443 -tls1_2 -brief 2>/dev/null | head -3' || echo "    openssl TLS 1.2 done"
echo ">>> Check probe output, then press Enter..."
read

echo ""
echo "=== 4. openssl s_client - TLS 1.3 ==="
echo "    To debug: echo Q | strace -e read,recvfrom,recvmsg openssl s_client -connect $TARGET:443 -tls1_3 2>&1 | grep '\\\\26\\\\3'"
sh -c 'echo "    PID: $$"; echo "Q" | exec openssl s_client -connect '"$TARGET"':443 -tls1_3 -brief 2>/dev/null | head -3' || echo "    openssl TLS 1.3 done"
echo ">>> Check probe output, then press Enter..."
read

echo ""
echo "=== 5. wget (GnuTLS or OpenSSL) ==="
if command -v wget &> /dev/null; then
    echo "    To debug: strace -e read,recvfrom,recvmsg wget -q --no-check-certificate -O /dev/null https://$TARGET 2>&1 | grep '\\\\26\\\\3'"
    sh -c 'echo "    PID: $$"; exec wget -q --no-check-certificate -O /dev/null https://'"$TARGET"'' && echo "    wget: OK" || echo "    wget failed"
    echo ">>> Check probe output, then press Enter..."
    read
else
    echo "wget not installed, skipping"
fi

echo ""
echo "=== 6. Python ssl module - TLS 1.2 ==="
echo "    To debug: strace -e read,recvfrom,recvmsg python3 -c \"import ssl,socket; ...\" 2>&1 | grep '\\\\26\\\\3'"
python3 -c "
import os
print(f'    PID: {os.getpid()}')
import ssl
import socket
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.minimum_version = ssl.TLSVersion.TLSv1_2
ctx.maximum_version = ssl.TLSVersion.TLSv1_2
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
with socket.create_connection(('$TARGET', 443)) as sock:
    with ctx.wrap_socket(sock, server_hostname='$TARGET') as ssock:
        print(f'    Python TLS 1.2: {ssock.version()}')
" 2>/dev/null || echo "    Python TLS 1.2 failed"
echo ">>> Check probe output, then press Enter..."
read

echo ""
echo "=== 7. Python ssl module - TLS 1.3 ==="
echo "    To debug: strace -e read,recvfrom,recvmsg python3 -c \"import ssl,socket; ...\" 2>&1 | grep '\\\\26\\\\3'"
python3 -c "
import os
print(f'    PID: {os.getpid()}')
import ssl
import socket
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
with socket.create_connection(('$TARGET', 443)) as sock:
    with ctx.wrap_socket(sock, server_hostname='$TARGET') as ssock:
        print(f'    Python TLS 1.3: {ssock.version()}')
" 2>/dev/null || echo "    Python TLS 1.3 failed"
echo ">>> Check probe output, then press Enter..."
read

echo ""
echo "=== 8. Go crypto/tls - TLS 1.2 ==="
if [ -f "./tls_test" ]; then
    echo "    To debug: strace -e read,recvfrom,recvmsg ./tls_test 1.2 2>&1 | grep '\\\\26\\\\3'"
    ./tls_test 1.2 2>/dev/null | grep -E "(TLS|Cipher|PID)" || echo "    Go TLS 1.2 done"
    echo ">>> Check probe output, then press Enter..."
    read
else
    echo "Go tls_test not built, run: go build -o tls_test tls_test_go.go"
fi

echo ""
echo "=== 9. Go crypto/tls - TLS 1.3 ==="
if [ -f "./tls_test" ]; then
    echo "    To debug: strace -e read,recvfrom,recvmsg ./tls_test 1.3 2>&1 | grep '\\\\26\\\\3'"
    ./tls_test 1.3 2>/dev/null | grep -E "(TLS|Cipher|PID)" || echo "    Go TLS 1.3 done"
    echo ">>> Check probe output, then press Enter..."
    read
else
    echo "Go tls_test not built"
fi

echo ""
echo "=== 10. Node.js (if available) ==="
if command -v node &> /dev/null; then
    echo "    To debug: strace -e read,recvfrom,recvmsg node -e \"require('https').get(...)\" 2>&1 | grep '\\\\26\\\\3'"
    node -e "
    console.log('    PID:', process.pid);
    const https = require('https');
    https.get('https://$TARGET', {rejectUnauthorized: false}, (res) => {
        console.log('    Node.js:', res.socket.getProtocol());
        res.destroy();
    }).on('error', (e) => console.log('    Node.js error:', e.message));
    " 2>/dev/null || echo "    Node.js failed"
    echo ">>> Check probe output, then press Enter..."
    read
else
    echo "Node.js not installed, skipping"
fi

echo ""
echo "=========================================="
echo "Done! All tests completed."
echo ""
echo "If probe missed something, use the strace commands above to find which syscall carries TLS."
echo "Look for: read(), recvfrom(), recvmsg(), or recv()"
echo "=========================================="
