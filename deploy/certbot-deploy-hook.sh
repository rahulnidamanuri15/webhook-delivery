#!/bin/sh
# Certbot deploy-hook: copies each renewed lineage to the flat paths nginx reads.
# Invoked by `certbot renew --deploy-hook <this script>` with RENEWED_LINEAGE
# (and RENEWED_DOMAINS) in the environment. No shell-variable interpolation
# happens at compose render time: certbot supplies RENEWED_LINEAGE only when
# this hook executes, so an inline `--deploy-hook "cp $RENEWED_LINEAGE/..."` in
# compose would expand too early. A dedicated script avoids that quoting trap.
set -eu

: "${RENEWED_LINEAGE:?RENEWED_LINEAGE is not set (must be run by certbot as a deploy-hook)}"

if [ ! -f "${RENEWED_LINEAGE}/fullchain.pem" ] || [ ! -f "${RENEWED_LINEAGE}/privkey.pem" ]; then
  echo "certbot-deploy-hook: expected certs missing under ${RENEWED_LINEAGE}" >&2
  exit 1
fi

cp "${RENEWED_LINEAGE}/fullchain.pem" /etc/letsencrypt/fullchain.pem
cp "${RENEWED_LINEAGE}/privkey.pem" /etc/letsencrypt/privkey.pem
chmod 644 /etc/letsencrypt/fullchain.pem
chmod 600 /etc/letsencrypt/privkey.pem
echo "certbot-deploy-hook: promoted certs for ${RENEWED_DOMAINS:-unknown domain} from ${RENEWED_LINEAGE}"
