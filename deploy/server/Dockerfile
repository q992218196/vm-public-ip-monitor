FROM composer:2 AS composer
FROM php:8.4-fpm-bookworm AS app
RUN apt-get update && apt-get install -y --no-install-recommends libpq-dev libicu-dev libzip-dev libonig-dev unzip gosu \
    && docker-php-ext-install pdo_pgsql intl mbstring zip opcache pcntl \
    && pecl install redis && docker-php-ext-enable redis \
    && rm -rf /var/lib/apt/lists/*
COPY --from=composer /usr/bin/composer /usr/local/bin/composer
WORKDIR /var/www/html
COPY server/ ./
RUN mkdir -p storage/framework/cache/data storage/framework/sessions storage/framework/views storage/app/private storage/logs bootstrap/cache \
    && composer install --no-dev --prefer-dist --no-interaction --optimize-autoloader \
    && php artisan filament:assets \
    && chown -R www-data:www-data storage bootstrap/cache
COPY deploy/server/php.ini /usr/local/etc/php/conf.d/monitor.ini
COPY deploy/server/entrypoint.sh /usr/local/bin/monitor-entrypoint
RUN chmod +x /usr/local/bin/monitor-entrypoint
ENTRYPOINT ["monitor-entrypoint"]
CMD ["php-fpm"]

FROM nginx:1.28-alpine AS web
COPY --from=app /var/www/html/public /var/www/html/public
COPY deploy/server/nginx.conf /etc/nginx/conf.d/default.conf
