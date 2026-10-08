FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    make \
    libc6-dev \
    libc6-dbg \
    git \
    wget \
    curl \
    ca-certificates \
    python3 \
    python3-dev \
    python3-pip \
    pkg-config \
    libpcre3-dev \
    zlib1g-dev \
    openssl \
    libssl-dev \
    clang \
    llvm \
    llvm-dev \
    automake \
    autoconf \
    libtool \
    cmake \
    ninja-build \
    meson \
    bison \
    flex \
    gdb \
    binutils \
    elfutils \
    strace \
    procps \
    psmisc \
    file \
    net-tools \
    vim \
    xz-utils \
    unzip \
    && rm -rf /var/lib/apt/lists/*

ENV CC=/usr/bin/gcc
ENV CXX=/usr/bin/g++

ENV AFL_VERSION=4.03c
ENV QILING_VERSION=1.4.6
ENV NGINX_VERSION=1.18.0

RUN pip3 install --no-cache-dir \
    qiling==${QILING_VERSION}

WORKDIR /opt

RUN wget -q \
        https://github.com/AFLplusplus/AFLplusplus/archive/refs/tags/${AFL_VERSION}.tar.gz \
    && tar xzf ${AFL_VERSION}.tar.gz \
    && mv AFLplusplus-${AFL_VERSION} AFLplusplus \
    && rm ${AFL_VERSION}.tar.gz \
    && cd /opt/AFLplusplus \
    && make -j"$(nproc)"

RUN cd /opt/AFLplusplus/unicorn_mode \
    && ./build_unicorn_support.sh || true

RUN python3 - <<'PY'
from pathlib import Path

base = Path("/root/.local/lib/python3.10/site-packages")

matches = list(
    base.glob("unicornafl-*.egg/unicornafl/unicornafl.py")
)

if not matches:
    print("unicornafl.py not found, patch skipped")
else:
    p = matches[0]

    text = p.read_text()

    needle = "import distutils"
    replacement = "import distutils\nimport distutils.sysconfig"

    if (
        needle in text
        and "import distutils.sysconfig" not in text
    ):
        text = text.replace(
            needle,
            replacement,
            1,
        )

        p.write_text(text)

        print(f"patched: {p}")
    else:
        print(f"no patch required: {p}")
PY

WORKDIR /opt

RUN wget -q \
        https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz \
    && tar xzf nginx-${NGINX_VERSION}.tar.gz \
    && cd nginx-${NGINX_VERSION} \
    && ./configure \
        --prefix=/usr \
        --sbin-path=/usr/sbin/nginx \
        --conf-path=/etc/nginx/nginx.conf \
        --error-log-path=/var/log/nginx/error.log \
        --pid-path=/tmp/nginx.pid \
        --lock-path=/var/lock/nginx.lock \
        --with-select_module \
        --with-pcre \
        --with-debug \
        --with-cc-opt="-O0 -g -fno-omit-frame-pointer" \
    && make -j"$(nproc)" \
    && make install \
    && rm /opt/nginx-${NGINX_VERSION}.tar.gz

RUN mkdir -p /etc/nginx

RUN cat > /etc/nginx/nginx.conf <<'EOF'
worker_processes 1;

master_process off;
daemon off;

error_log stderr debug;

pid /tmp/nginx.pid;

events {
    worker_connections 1024;
    use select;
    multi_accept off;
}

http {
    access_log off;

    server {
        listen 127.0.0.1:8080;

        location / {
            return 200 "OK";
        }
    }
}
EOF

RUN nginx -v
RUN nginx -V 2>&1

RUN mkdir -p \
        /var/log/nginx \
        /var/lib/nginx/body \
        /var/lib/nginx/proxy \
        /var/lib/nginx/fastcgi \
        /var/lib/nginx/scgi \
        /var/lib/nginx/uwsgi \
        /tmp \
    && touch /var/log/nginx/error.log \
    && chmod 666 /var/log/nginx/error.log \
    && chmod 777 /tmp \
    && chmod 777 /var/lib/nginx

RUN mkdir -p /opt/rootfs && \
    cp -a /bin /opt/rootfs/ && \
    cp -a /sbin /opt/rootfs/ && \
    cp -a /lib /opt/rootfs/ && \
    cp -a /lib64 /opt/rootfs/ && \
    cp -a /usr /opt/rootfs/ && \
    cp -a /etc /opt/rootfs/

RUN mkdir -p \
        /opt/rootfs/tmp \
        /opt/rootfs/var/log/nginx \
        /opt/rootfs/var/lib/nginx/body \
        /opt/rootfs/var/lib/nginx/proxy \
        /opt/rootfs/var/lib/nginx/fastcgi \
        /opt/rootfs/var/lib/nginx/scgi \
        /opt/rootfs/var/lib/nginx/uwsgi \
    && touch /opt/rootfs/var/log/nginx/error.log \
    && chmod 666 /opt/rootfs/var/log/nginx/error.log \
    && chmod 777 /opt/rootfs/tmp \
    && chmod 777 /opt/rootfs/var/lib/nginx

RUN /opt/rootfs/usr/sbin/nginx \
        -t \
        -c /opt/rootfs/etc/nginx/nginx.conf

RUN file /usr/sbin/nginx

RUN nm -n /usr/sbin/nginx | grep -E \
        'ngx_unix_recv|ngx_http_process_request' \
        || true


WORKDIR /work

ENV ROOTFS=/opt/rootfs
ENV NGINX_BIN=/opt/rootfs/usr/sbin/nginx
ENV NGINX_GDB_BIN=/usr/sbin/nginx
ENV NGINX_CONF=/etc/nginx/nginx.conf
ENV AFL_PATH=/opt/AFLplusplus

CMD ["/bin/bash"]