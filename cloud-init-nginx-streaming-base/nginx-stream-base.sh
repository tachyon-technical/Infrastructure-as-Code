#!/usr/bin/env bash

NGINX="https://nginx.org"
OPENSSL="https://www.openssl.org"
LOG_FILE="/tmp/cloudinit.log"

OPENSSL_LATEST=$(wget -qO- --no-check-certificate $OPENSSL/source/ |
	grep -Eo 'openssl-[A-Za-z0-9\.]+.tar.gz' |
	sort -V | tail -1 | sed -nre 's|^[^0-9]*(([0-9]+\.)*[A-Za-z0-9]+).tar.*|\1|p')

NGINX_LATEST=$(wget -qO- --no-check-certificate $NGINX/download/ |
	grep -Eo 'nginx-[A-Za-z0-9\.]+.tar.gz' |
	sort -V | tail -1 | sed -nre 's|^[^0-9]*(([0-9]+\.)*[A-Za-z0-9]+).tar.*|\1|p')

NGINX_CONFIG=$(
	cat <<EOF
./configure --prefix=/var/www/html \
--sbin-path=/usr/sbin/nginx \
--modules-path=/etc/nginx/modules \
--conf-path=/etc/nginx/nginx.conf \
--error-log-path=/var/log/nginx/error.log \
--http-log-path=/var/log/nginx/access.log \
--pid-path=/etc/nginx/nginx.pid \
--lock-path=/etc/nginx/nginx.lock \
--user=www-data \
--group=www-date \
--with-threads \
--with-file-aio \
--with-http_ssl_module \
--with-http_v2_module \		
--with-http_v3_module \
--with-http_mp4_module \
--with-http_flv_module \
--with-compat \
--with-pcre-jit \
--without-http_auth_basic_module \
--without-http_geo_module \
--without-http_fastcgi_module \
--without-http_uwsgi_module \
--without-http_scgi_module \
--without-http_grpc_module \
--without-http_memcached_module \
--with-cc-opt="-O3 -march=native"
EOF
)

NGINX_SYSTEMD_UNIT=$(
	cat <<EOF
[Unit]
Description=A custom-compiled Nginx server
After=network-online.target remote-fs.target nss-lookup.target
Wants=network-online.target

[Service]
Type=forking
PIDFile=/etc/nginx/nginx.pid
ExecStartPre=/usr/sbin/nginx -t -q -g 'daemon on; master_process on;'
ExecStart=/usr/sbin/nginx -g 'daemon on; master_process on;'
ExecReload=/usr/sbin/nginx -g 'daemon on; master_process on;' -s reload
ExecStop=-/sbin/start-stop-daemon --quiet --stop --retry QUIT/5 --pidfile /etc/nginx/nginx.pid
TimeoutStopSec=5
KillMode=mixed

[Install]
WantedBy=multi-user.target
EOF
)

function execute_and_log {
	if
		CMD_LINE=$2
		eval "$1" >/dev/null 2>&1
	then
		echo -e "\tSuccess. [Line $CMD_LINE]" >>$LOG_FILE
	else
		echo -e "\tError. [Line $CMD_LINE]" >>$LOG_FILE
	fi
}

echo "Running updates." >>$LOG_FILE
execute_and_log "apt-get update -y" $LINENO

echo "Installing dependencies." >>$LOG_FILE
execute_and_log "apt-get install git build-essential libpcre3 libpcre3-dev \
	zlib1g zlib1g-dev libssl-dev libgd-dev libxml2 libxml2-dev \
	uuid-dev ca-certificates" $LINENO

echo "Changing to /tmp." >>$LOG_FILE
execute_and_log "cd /tmp" $LINENO

echo "Downloading OpenSSL." >>$LOG_FILE
execute_and_log "wget -qN ${OPENSSL}/source/openssl-${OPENSSL_LATEST}.tar.gz \
                 -O /tmp/openssl-${OPENSSL_LATEST}.tar.gz" $LINENO

echo "Importing OpenSSL public key." >>$LOG_FILE
execute_and_log "gpg --recv-keys BA5473A2B0587B07FB27CF2D216094DFD0CB81EF" $LINENO

echo "Downloading OpenSSL digital signature." >>$LOG_FILE
execute_and_log "wget -qN ${OPENSSL}/source/openssl-${OPENSSL_LATEST}.tar.gz.asc \
  -O /tmp/openssl-${OPENSSL_LATEST}.tar.gz.asc" $LINENO

echo "Checking OpenSSL digital signature." >>$LOG_FILE
execute_and_log "gpg --verify /tmp/openssl-${OPENSSL_LATEST}.tar.gz.asc \
	/tmp/openssl-${OPENSSL_LATEST}.tar.gz" $LINENO

echo "Downloading Nginx." >>$LOG_FILE
execute_and_log "wget -qN ${NGINX}/download/nginx-${NGINX_LATEST}.tar.gz \
	-O /tmp/nginx-${NGINX_LATEST}.tar.gz" $LINENO

echo "Downloading Nginx public key." >>$LOG_FILE
execute_and_log "wget -qN ${NGINX}/keys/nginx_signing.key \
	-O /tmp/nginx_signing.key" $LINENO

echo "Importing Nginx public key." >>$LOG_FILE
execute_and_log "gpg --quiet --import /tmp/nginx_signing.key" $LINENO

echo "Downloading Nginx digital signature." >>$LOG_FILE
execute_and_log "wget -qN ${NGINX}/download/nginx-${NGINX_LATEST}.tar.gz.asc \
	-O /tmp/nginx-${NGINX_LATEST}.tar.gz.asc" $LINENO

echo "Extracting OpenSSL." >>$LOG_FILE
execute_and_log "cd /tmp && tar -xvzf openssl-${OPENSSL_LATEST}.tar.gz && \
	cd openssl-${OPENSSL_LATEST}" $LINENO

echo "Configuring OpenSSL." >>$LOG_FILE
execute_and_log "./config no-weak-ssl-ciphers no-ssl3 no-tls1 no-tls1_1 \
  no-idea no-psk no-srp no-des no-rc2 no-rc4 no-rc5 no-md2 no-md4 no-mdc2 \
	--prefix=/usr zlib-dynamic --openssldir=/etc/ssl shared" $LINENO

echo "Building OpenSSL." >>$LOG_FILE
execute_and_log "make -j$(nproc) install_sw && ldconfig /usr/lib64/ && \
	ldconfig /usr/lib/x86_64-linux-gnu/" $LINENO

echo "Extracting Nginx." >>$LOG_FILE
execute_and_log "cd /tmp && tar -xvzf nginx-${NGINX_LATEST}.tar.gz && \
	cd nginx-${NGINX_LATEST}" $LINENO

echo "Configuring Nginx." >>$LOG_FILE
execute_and_log "$NGINX_CONFIG" $LINENO

echo "Building Nginx." >>$LOG_FILE
execute_and_log "make -j$(nproc) install" $LINENO

echo "Configuring SystemD daemon."
execute_and_log "echo $NGINX_SYSTEMD_UNIT > /usr/lib/systemd/system/nginx.service && \
	systemctl daemon-reload && touch /etc/nginx/nginx.pid && \
	chown www-data:www-date /etc/nginx/nginx.pid && \
	systemctl start nginx.service" $LINENO
