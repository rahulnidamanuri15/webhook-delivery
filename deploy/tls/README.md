# TLS Certificates for Reverse Proxy

Place your production TLS certificates here:
- `fullchain.pem` (Certificate chain)
- `privkey.pem` (Private key)

### Generate Self-Signed Certificates (for Staging / Local TLS Testing)
Run:
```bash
python scripts/generate_dev_certs.py
```
or via OpenSSL:
```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout deploy/tls/privkey.pem \
  -out deploy/tls/fullchain.pem \
  -subj "/CN=localhost"
```

For production, obtain valid certificates using Certbot / Let's Encrypt or your cloud provider.
