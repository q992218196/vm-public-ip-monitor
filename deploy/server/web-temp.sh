#!/bin/sh
set -eu
mkdir -p /var/log/nginx/client_temp
chown nginx:nginx /var/log/nginx/client_temp
chmod 700 /var/log/nginx/client_temp
