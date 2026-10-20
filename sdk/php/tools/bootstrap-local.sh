#!/bin/sh
# Optional developer-only bootstrap. Never runs during Composer install or SDK use.
set -eu
cd "$(dirname "$0")/.."
TASK_PHP_ROOT="$PWD"
TASK_OPENSSL_PREFIX="${1:?Pass the existing OpenSSL prefix containing include/openssl and lib/libssl/libcrypto}"
mkdir -p .tools .evidence
cd .tools
if [ ! -f php-8.5.11.tar.xz ]; then
  curl --fail --location --retry 2 https://www.php.net/distributions/php-8.5.11.tar.xz -o php-8.5.11.tar.xz
fi
printf '%s  %s\n' d9be75c08e8c316f4c8f4194d8fbe1750a15f6a6d9d4e3fe72082abeeb800360 php-8.5.11.tar.xz | shasum -a 256 --check
if [ ! -d php-8.5.11 ]; then tar -xf php-8.5.11.tar.xz; fi
ZLIB_LIBS=-lz OPENSSL_CFLAGS="-I$TASK_OPENSSL_PREFIX/include" OPENSSL_LIBS="-L$TASK_OPENSSL_PREFIX/lib -lssl -lcrypto" PKG_CONFIG=/usr/bin/true ./php-8.5.11/configure --prefix="$PWD/runtime" --disable-all --enable-cli --disable-cgi --disable-phpdbg --enable-phar --enable-filter --enable-tokenizer --enable-ctype --enable-mbstring --disable-mbregex --with-openssl --with-zlib > "$TASK_PHP_ROOT/.evidence/configure.log" 2>&1
make -j6 > "$TASK_PHP_ROOT/.evidence/build.log" 2>&1
./sapi/cli/php -n --version
curl --fail --location --retry 2 https://getcomposer.org/download/2.10.3/composer.phar -o composer.phar
printf '%s  %s\n' 7a2d379d5b8ffdaa028580ef26494c36d2feef4b178d3dd1473a4dbc5e17c8d6 composer.phar | shasum -a 256 --check
