#!/usr/bin/env bash

BROTLI="https://github.com/google/brotli"
ZLIB="https://www.zlib.net/current/zlib.tar.gz"
ZSTD="https://github.com/facebook/zstd"
PCRE2="https://github.com/PCRE2Project/pcre2"
LIBATOMIC="https://github.com/ivmai/libatomic_ops"
OPENSSL="https://www.openssl.org"
NGINX="https://nginx.org"

LOG_FILE="/tmp/cloudinit.log"
ERR_FILE="/tmp/cloudinit_err.log"

read OPENSSL_LATEST < <(wget -qO- --no-check-certificate $OPENSSL/source/ |
	grep -Eo 'openssl-[A-Za-z0-9\.]+.tar.gz' | \
	sort -V | tail -1 | sed -nre 's|^[^0-9]*(([0-9]+\.)*[A-Za-z0-9]+).tar.*|\1|p')

read NGINX_LATEST < <(wget -qO- --no-check-certificate $NGINX/download/ |
	grep -Eo 'nginx-[A-Za-z0-9\.]+.tar.gz' | \
	sort -V | tail -1 | sed -nre 's|^[^0-9]*(([0-9]+\.)*[A-Za-z0-9]+).tar.*|\1|p')

read BROTLI_LATEST < <(cut -c5- <<< $(curl -s -L --insecure "$BROTLI/releases/latest" | \
		grep -Eo "tag/v[0-9\.]+" | uniq))
  
read ZLIB_LATEST < <(curl -s -L --insecure "https://www.zlib.net/fossils/?C=M;O=D"  | \
	    grep -Eo "zlib-[0-9\.]+" | sort -u -r | sed -n '1p' | \
    	    sed -r 's|zlib-([0-9\.]+)\.|\1|')

read ZSTD_LATEST < <(cut -c6- <<< $(curl -s -L --insecure "$ZSTD/releases/latest" | \
                grep -Eo "tag/v[0-9\.]+" | uniq ))

read PCRE2_LATEST < <(curl -s -L --insecure "$PCRE2/releases/latest" | \
	     grep -o "pcre2-[0-9\.]\{3,\}" | \
      	     grep -Eo "([0-9]{1,3}\.)[0-9]+" | uniq )

read LIBATOMIC_LATEST < <(cut -c5- <<< $(curl -s -L --insecure "$LIBATOMIC/releases/latest" | \
		grep -Eo "tag/v[0-9\.]+" | uniq )

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
--group=www-data \
--with-threads \
--with-file-aio \
--with-http_ssl_module \
--with-http_v2_module \
--with-http_v3_module \
--with-http_mp4_module \
--with-http_flv_module \
--with-http_secure_link_module \
--with-compat \
--with-pcre-jit \
--without-http_auth_basic_module \
--without-http_geo_module \
--without-http_fastcgi_module \
--without-http_uwsgi_module \
--without-http_scgi_module \
--without-http_grpc_module \
--without-http_memcached_module \
--with-cc-opt="-O3 -march=native -funroll-loops -ffast-math -I /opt/usr/local/include/openssl/ \
   -I /opt/usr/local/include/ -I /opt/usr/local/include/atomic_ops" \
--with-ld-opt="-L /opt/usr/local/lib -ldl -Wl,-rpath,/opt/usr/local/lib"
EOF
)

## These can be added if compiling alongside OpenSSL
## --with-openssl= \
## --with-openssl-opt=enable-ktls \

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

GCC_PROCS=1
if [[ "$PROCS" -le 3 ]]; 
  then GCC_PROCS=1; 
elif [[ "$PROCS" -ge 4 ]] && [[ "$PROCS" -le 7 ]]; 
  then GCC_PROCS=2; 
elif [[ "$PROCS" -ge 8 ]] && [[ "$PROCS" -le 13 ]]; 
  then GCC_PROCS=4; 
else 
  GCC_PROCS=6; fi

function execute_and_log {
	if
		CMD_LINE=$2
  		eval "$1" >/dev/null 2>>$ERR_FILE
	then
		echo -e "\tSuccess. [Line $CMD_LINE]" >>$LOG_FILE
	else
		echo -e "\tError. [Line $CMD_LINE]" >>$LOG_FILE
	fi
}

echo "Running updates." >>$LOG_FILE
execute_and_log "apt-get update -y" $LINENO

echo "Installing dependencies." >>$LOG_FILE
execute_and_log "apt-get install -y git build-essential libpcre3 libpcre3-dev \
	zlib1g zlib1g-dev libssl-dev libgd-dev libxml2 libxml2-dev \
	uuid-dev ca-certificates" $LINENO

echo "Changing to /tmp." >>$LOG_FILE
execute_and_log "cd /tmp" $LINENO


###### AUTOMATE THIS
: '
wget https://github.com/google/brotli/archive/refs/tags/v1.1.0.tar.gz
tar xzf v1.1.0.tar.gz
cd brotli-1.1.0/
cmake -DCMAKE_INSTALL_PREFIX=/opt/usr/local -DCMAKE_LIBRARY_PATH=/opt/usr/local/lib64 -DCMAKE_BINARY_DIR=/opt/usr/local/bin -DCMAKE_CXX_FLAGS="-O3 -march=native -funroll-loops" -DCMAKE_C_FLAGS="-O3 -march=native -funroll-loops"
make 
make install

wget   https://www.zlib.net/current/zlib.tar.gz
tar xzf zlib.tar.gz
cd zlib-1.3.1l
setenv CFLAGS="-O3 -march=native -funroll-loops"

./configure --prefix=/opt/usr/local --includedir=/opt/usr/local/include --libdir=/opt/usr/local/lib
make 
make -n install
make install

wget https://github.com/facebook/zstd/releases/download/v1.5.6/zstd-1.5.6.tar.gz
tar xzf zstd-1.5.6.tar.gz
cd zstd-1.5.6
export INCLUDEDIR="/opt/usr/local/include"
export LIBDIR="/opt/usr/local/lib"
export PREFIX="/opt/usr/local/"
make
make install

wget https://github.com/PCRE2Project/pcre2/releases/download/pcre2-10.44/pcre2-10.44.tar.bz2
ar xvf pcre2-10.44.tar.bz2
cd pcre2-10.44/

./configure --prefix=/opt/usr/local --exec-prefix=/opt/usr/local --libdir=/opt/usr/local/lib --includedir=/opt/usr/local/include --enable-jit
make -j
make -n install
make install

https://github.com/ivmai/libatomic_ops/releases/download/v7.8.2/libatomic_ops-7.8.2.tar.gz
tar xzf libatomic_ops-7.8.2.tar.gz
cd libatomic_ops-7.8.2/

./configure --prefix=/opt/usr/local --exec-prefix=/opt/usr/local --libdir=/opt/usr/local/lib --includedir=/opt/usr/local/include
'


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

# Derp verify digital signature

echo "Extracting OpenSSL." >>$LOG_FILE
execute_and_log "cd /tmp && tar -xvzf openssl-${OPENSSL_LATEST}.tar.gz && \
	cd openssl-${OPENSSL_LATEST}" $LINENO

echo "Configuring OpenSSL." >>$LOG_FILE
execute_and_log "./config \
  enable-ktls no-weak-ssl-ciphers no-ssl3 no-ssl3-method no-tls1 no-tls1_1 \
  no-idea no-psk no-srp no-srtp no-des no-rc2 no-rc4 no-rc5 no-md2 no-md4 no-mdc2  \
  no-legacy no-gost threads \
  enable-brotli --with-brotli-lib=/opt/usr/local/lib --with-brotli-include=/opt/usr/local/include/brotli \
  zlib-dynamic --with-zlib-lib=/opt/usr/local/lib --with-zlib-include=/opt/usr/local/include \
  enable-zstd-dynamic --with-zstd-lib=/opt/usr/local/lib --with-zstd-include=/opt/usr/local/include/\
  --prefix=/opt/usr/local \
  --openssldir=/opt/usr/local/openssl \
  --libdir=/opt/usr/local/lib" $LINENO 

echo "Building OpenSSL." >>$LOG_FILE
execute_and_log "make install_sw" $LINENO

#echo "Linking libraries." >>$LOG_FILE
#execute_and_log "ldconfig /usr/lib64/" $LINENO

echo "Extracting Nginx." >>$LOG_FILE
execute_and_log "cd /tmp && tar -xvzf nginx-${NGINX_LATEST}.tar.gz && \
	cd nginx-${NGINX_LATEST}" $LINENO

echo "Configuring Nginx." >>$LOG_FILE
execute_and_log "$NGINX_CONFIG" $LINENO

echo "Building Nginx." >>$LOG_FILE
execute_and_log "make -j$GCC_PROCS install" $LINENO

echo "Creating Nginx PID file" >>$LOG_FILE
execute_and_log "sed -i -Ee 's|^#?pid.*$|pid  /etc/nginx/nginx.pid;|' \
  -e 's|^#?user.*$|user  www-data;|' /etc/nginx/nginx.conf && touch /etc/nginx/nginx.pid && \
  chown www-data:www-data /etc/nginx/nginx.pid"  $LINENO

echo "Configuring SystemD daemon."
execute_and_log 'echo "$NGINX_SYSTEMD_UNIT" > /usr/lib/systemd/system/nginx.service && \
	systemctl daemon-reload && \
	systemctl start nginx.service' $LINENO
