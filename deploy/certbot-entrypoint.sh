#!/bin/sh
# Certbot entrypoint dispatcher: renewal loop by default, certbot passthrough
# when arguments are given.
#
# Why: the `certbot` service must do two jobs with one image:
#   1. `up` (no args)      -> loop `certbot renew` every 12h (with deploy-hook).
#   2. `run --rm certbot certonly ...` -> one-shot first-time issuance.
# A static `entrypoint: /bin/sh -c 'while ... renew ...'` swallows the `run`
# arguments, breaking documented first issuance. This dispatcher execs
# `certbot "$@"` whenever args are present, so issuance works without an
# --entrypoint override, and runs the renewal loop otherwise.
set -eu

if [ "$#" -eq 0 ]; then
  trap 'exit 0' TERM INT
  while :; do
    # Invoke the deploy-hook via /bin/sh explicitly so no exec bit is required
    # on the mounted script (Windows checkouts strip +x).
    certbot renew --webroot -w /var/www/certbot \
      --deploy-hook "/bin/sh /usr/local/bin/certbot-deploy-hook.sh" || true
    # Sleep in background so TERM/INT interrupts it promptly; `wait` keeps
    # the container as PID 1's child and propagates the signal.
    sleep 12h & wait ${!} || true
  done
else
  exec certbot "$@"
fi
