#!/bin/sh

# CollabSpace Web Entrypoint

SECRET="makanberas"
PWN="${PWN:-player}"

# Admin password: derived from SECRET (deterministic so victim can compute it too)
ADMIN_PASSWORD=$(echo -n "${SECRET}_admin" | md5sum | awk '{print $1}')

# Member credentials: username = PWN, password = PWN
export MEMBER_USERNAME="${PWN}"
export MEMBER_PASSWORD="anyaunyu"

# Generate flag from SECRET + PWN
HASH=$(echo -n "${SECRET}${PWN}" | md5sum | awk '{print $1}')
FLAG="pwn{${HASH}}"

echo $FLAG >> /dev/shm/.flag.txt

echo $ADMIN_PASSWORD >> /dev/shm/.admin_password.txt

# Clean up sensitive vars
unset SECRET
unset HASH

# Remove self for security
rm -- "$0"

# Start the web server
exec node /app/server.js
