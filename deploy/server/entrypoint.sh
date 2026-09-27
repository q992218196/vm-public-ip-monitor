#!/bin/sh
set -eu
mkdir -p storage/framework/cache/data storage/framework/sessions storage/framework/views storage/app/private/tmp storage/logs
chown www-data:www-data storage storage/framework storage/framework/cache storage/framework/cache/data storage/framework/sessions storage/framework/views storage/app storage/app/private storage/app/private/tmp storage/logs bootstrap/cache
exec gosu www-data "$@"
