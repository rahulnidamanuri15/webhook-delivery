# TLS Certificates for Reverse Proxy

Place your production TLS certificates here:
- `fullchain.pem` (Certificate chain)
- `privkey.pem` (Private key)

### Production (Let's Encrypt via the `certbot` service in compose.prod.yaml)

Point your domain at the VM, open ports 80/443 in the VCN security list, and
issue certs with certbot (webroot against the reverse proxy):

```bash
# 1. Start the HTTP stack first (ACME webroot served on :80):
NGINX_CONF=./deploy/nginx.oracle-http.conf DEPLOY_PROD_ALLOW_MISSING_TLS=1 \
  ./scripts/deploy_prod.sh up --build -d

# 2. Issue the first certificate (webroot against reverse_proxy):
docker compose -f compose.yaml -f compose.prod.yaml run --rm certbot \
  certonly --webroot -w /var/www/certbot \
  -d hooks.example.com --email you@example.com --agree-tos --non-interactive

# 3. Promote lineage to the flat paths nginx reads, then switch to TLS:
cp deploy/tls/live/hooks.example.com/fullchain.pem deploy/tls/fullchain.pem
cp deploy/tls/live/hooks.example.com/privkey.pem deploy/tls/privkey.pem
chmod 644 deploy/tls/fullchain.pem
chmod 600 deploy/tls/privkey.pem
./scripts/deploy_prod.sh up --build -d
```

Renewals are automatic: the `certbot` service loops `renew --webroot`
every 12h with a `--deploy-hook` that copies each renewed lineage to the
flat `fullchain.pem`/`privkey.pem`, and `reverse_proxy` reloads nginx every
12h to pick them up (zero-downtime, no hardcoded domain in `nginx.conf`).

### Self-signed fallback (staging / local TLS testing only)

```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout deploy/tls/privkey.pem \
  -out deploy/tls/fullchain.pem \
  -subj "/CN=localhost"
```

Never commit real certificates: `*.pem` is git-ignored and docker-ignored.
