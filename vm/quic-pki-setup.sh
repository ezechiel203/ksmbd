#!/bin/bash
# quic-pki-setup.sh - Generate test PKI/certs for QUIC proxy in VM

set -euo pipefail

cert_dir="/etc/ksmbd/quic"
mkdir -p "$cert_dir"

if [ ! -f "$cert_dir/ca.key" ] || [ ! -f "$cert_dir/ca.crt" ]; then
    openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 \
        -nodes -keyout "$cert_dir/ca.key" -out "$cert_dir/ca.crt" \
        -subj "/CN=ksmbd-quic-test-ca" >/dev/null 2>&1
fi

if [ ! -f "$cert_dir/server.key" ] || [ ! -f "$cert_dir/server.crt" ]; then
    openssl req -new -newkey rsa:2048 -nodes \
        -keyout "$cert_dir/server.key" -out "$cert_dir/server.csr" \
        -subj "/CN=localhost" >/dev/null 2>&1

    cat > "$cert_dir/server.ext" <<'EOF'
subjectAltName=DNS:localhost,IP:127.0.0.1
extendedKeyUsage=serverAuth
EOF

    openssl x509 -req -in "$cert_dir/server.csr" \
        -CA "$cert_dir/ca.crt" -CAkey "$cert_dir/ca.key" -CAcreateserial \
        -out "$cert_dir/server.crt" -days 825 -sha256 \
        -extfile "$cert_dir/server.ext" >/dev/null 2>&1
fi

if [ ! -f "$cert_dir/client.key" ] || [ ! -f "$cert_dir/client.crt" ]; then
    openssl req -new -newkey rsa:2048 -nodes \
        -keyout "$cert_dir/client.key" -out "$cert_dir/client.csr" \
        -subj "/CN=ksmbd-quic-test-client" >/dev/null 2>&1

    cat > "$cert_dir/client.ext" <<'EOF'
extendedKeyUsage=clientAuth
EOF

    openssl x509 -req -in "$cert_dir/client.csr" \
        -CA "$cert_dir/ca.crt" -CAkey "$cert_dir/ca.key" -CAcreateserial \
        -out "$cert_dir/client.crt" -days 825 -sha256 \
        -extfile "$cert_dir/client.ext" >/dev/null 2>&1
fi

chmod 600 "$cert_dir"/*.key
chmod 644 "$cert_dir"/*.crt

echo "QUIC PKI artifacts ready at $cert_dir"
