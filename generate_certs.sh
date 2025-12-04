#!/bin/bash

# Create certs directory
mkdir -p certs
cd certs

echo "=== 1. Generating Certificate Authority (CA) Key and Root Certificate ==="
# Generate CA Private Key
openssl genrsa -out ca.key 4096

# Generate CA Root Certificate (valid for 365 days)
openssl req -x509 -new -nodes -key ca.key -sha256 -days 365 -out ca.crt -subj "/C=PT/ST=Aveiro/L=Aveiro/O=SecureShare/OU=Security/CN=SecureShareRootCA" -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"

echo "=== 2. Generating Server Key and CSR ==="
# Generate Server Private Key
openssl genrsa -out server.key 2048

# Generate Server CSR (Certificate Signing Request)
openssl req -new -key server.key -out server.csr -subj "/C=PT/ST=Aveiro/L=Aveiro/O=SecureShare/OU=Backend/CN=localhost"

echo "=== 3. Signing Server Certificate with CA ==="
# Create a config file for extensions (Subject Alternative Name)
cat > server.ext << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
EOF

# Sign the CSR with the CA key/cert
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365 -sha256 -extfile server.ext

echo "=== Certificates Generated Successfully in certs/ ==="
ls -l
