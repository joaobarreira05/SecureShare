# Certificate Authority (CA) & HTTPS Implementation

## Overview
To secure communication between clients and the SecureShare server, we implemented a **Private Certificate Authority (CA)**. This allows us to issue valid SSL/TLS certificates for `localhost` (or any other domain) that are trusted by our clients, enabling full HTTPS support without relying on public CAs (like Let's Encrypt) which cannot validate local domains.

## The Chain of Trust
1.  **Root CA**: We generated a self-signed Root Certificate (`ca.crt`) and a private key (`ca.key`). This acts as the ultimate source of trust.
2.  **Server Certificate**: We generated a certificate for the server (`server.crt`) that is **signed by our Root CA**.
3.  **Trust**: Clients (like our test script or a browser) are configured to trust the **Root CA**. Because the Server Certificate is signed by the trusted Root CA, the client trusts the server.

## Implementation Details (`generate_certs.sh`)

The `generate_certs.sh` script automates the entire process in three steps:

### Step 1: Generate the CA
We create the Root CA's private key and self-signed certificate.
```bash
# Generate CA Private Key
openssl genrsa -out ca.key 4096

# Generate CA Root Certificate
# CRITICAL: We add 'basicConstraints=CA:TRUE' and 'keyUsage=keyCertSign' 
# to explicitly mark this as a Certificate Authority that can sign other certs.
openssl req -x509 -new -nodes -key ca.key -sha256 -days 365 -out ca.crt \
    -subj "/C=PT.../CN=SecureShareRootCA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"
```

### Step 2: Generate Server Key & CSR
We create the Server's private key and a **Certificate Signing Request (CSR)**. The CSR contains the server's details (like `CN=localhost`) but is not yet a valid certificate.
```bash
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -subj "/.../CN=localhost"
```

### Step 3: Sign the Server Certificate
We use the **CA's Key and Certificate** to sign the Server's CSR, creating the valid `server.crt`.
```bash
# We use a config file to add Subject Alternative Names (SANs).
# This is required for modern browsers/clients to trust 'localhost' and '127.0.0.1'.
cat > server.ext << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
EOF

# Sign the CSR
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -days 365 -sha256 -extfile server.ext
```

## Usage

### Server Side (Uvicorn)
The server is started with the **Server Certificate** and **Server Key**. It sends `server.crt` to any connecting client.
```bash
uvicorn backend.app.main:app ... --ssl-keyfile=certs/server.key --ssl-certfile=certs/server.crt
```

### Client Side (Python Requests)
The client must possess the **Root CA Certificate** (`ca.crt`) to verify the server's identity.
```python
import requests

# We tell requests to use our local CA cert for verification
requests.get("https://localhost:8000", verify="certs/ca.crt")
```
Alternatively, setting the environment variable `REQUESTS_CA_BUNDLE` to the path of `ca.crt` works globally for the process.
