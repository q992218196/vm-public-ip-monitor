FROM node:24-bookworm-slim AS frontend
WORKDIR /src
COPY admin/web/package.json admin/web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY admin/web/ ./
RUN npm run typecheck && npm run build

FROM composer:2 AS composer
FROM php:8.4-fpm-bookworm AS app
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev libzip-dev libpng-dev libjpeg62-turbo-dev libfreetype6-dev libonig-dev unzip gosu \
    && docker-php-ext-configure gd --with-freetype --with-jpeg \
    && docker-php-ext-install pdo_mysql pdo_pgsql bcmath gd mbstring zip opcache \
    && rm -rf /var/lib/apt/lists/*
COPY --from=composer /usr/bin/composer /usr/local/bin/composer
WORKDIR /var/www/html
COPY admin/ ./
RUN mkdir -p runtime public/uploads \
    && composer install --no-dev --prefer-dist --no-interaction --optimize-autoloader \
    && rm -rf public/install \
    && touch public/install.lock \
    && chown -R www-data:www-data runtime public/uploads
COPY --from=frontend /src/dist/ /var/www/html/public/
COPY deploy/buildadmin/php.ini /usr/local/etc/php/conf.d/buildadmin.ini
COPY deploy/buildadmin/entrypoint.sh /usr/local/bin/buildadmin-entrypoint
RUN chmod +x /usr/local/bin/buildadmin-entrypoint
ENTRYPOINT ["buildadmin-entrypoint"]
CMD ["php-fpm"]

FROM nginx:1.28-alpine AS web
COPY --from=app /var/www/html/public /var/www/html/public
COPY deploy/buildadmin/nginx.conf /etc/nginx/conf.d/default.conf
