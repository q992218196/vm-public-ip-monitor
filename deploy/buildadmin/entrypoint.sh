#!/bin/sh
set -eu
mkdir -p runtime public/uploads
chown www-data:www-data runtime public/uploads
if [ "$1" = "php-fpm" ]; then
    exec "$@"
fi
exec gosu www-data "$@"
