FROM envoyproxy/envoy:contrib-v1.34.1
RUN apt -y update \
    && apt install -y \
    apt-utils \
    autoconf \
    automake \
    build-essential \
    git \
    libcurl4-openssl-dev \
    libgeoip-dev \
    liblmdb-dev \
    libpcre2-dev \
    libtool \
    libxml2-dev \
    libyajl-dev \
    pkgconf \
    wget \
    zlib1g-dev \
    curl \
    gcc \
    g++ \
    gdb \
    clang \
    make \
    ninja-build \
    cmake \
    valgrind \
    locales-all \
    dos2unix \
    rsync \
    tar
RUN apt clean \
    && git clone \
     --depth 1 \
     -b v3/master \
     --single-branch https://github.com/owasp-modsecurity/ModSecurity
RUN cd /ModSecurity \
    && git submodule init \
    && git submodule update \
    && ./build.sh \
    && ./configure \
    && make \
    && make install
