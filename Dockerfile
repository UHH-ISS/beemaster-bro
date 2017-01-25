FROM debian:stretch

RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    bison \
    flex \
    gawk \
    cmake \
    swig \
    libssl1.0-dev \
    libgeoip-dev \
    python \
    python-dev \
    libcurl4-openssl-dev \
    wget \
    libncurses5-dev \
    ca-certificates \
    librocksdb-dev \
    libpcap-dev \
    zlib1g-dev \
    libtcmalloc-minimal4 \
    curl \
    google-perftools \
    debhelper \
    bc \
    --no-install-recommends

# get actor framwork
# RUN git clone https://github.com/actor-framework/actor-framework.git caf
# installing from source does not work, >v0.14.5 is too new...

WORKDIR /scratch
RUN curl -LO https://github.com/actor-framework/actor-framework/archive/0.14.5.tar.gz
RUN tar xzf 0.14.5.tar.gz

WORKDIR /scratch/actor-framework-0.14.5
RUN ./configure
RUN make -j4 install


# get bro repository
WORKDIR /scratch
RUN git clone --recursive https://github.com/bro/bro /scratch/bro-git
WORKDIR /scratch/bro-git

# use correct branches / submodules, tie the version to "multihop working" (3b46716)
RUN git checkout topic/mfischer/deep-cluster && \
    git submodule update && \
    git checkout 3b46716 && \
    cd aux/broker && \
    git checkout topic/mfischer/broker-multihop && \
    cd ../..

RUN ./configure --disable-broccoli --disable-python
RUN make -j4 install

WORKDIR /bro

# the dionaea_receiver.bro needs this port:
EXPOSE 9999

COPY config/etc /usr/local/bro/etc

# Copy shared scripts
COPY scripts\_shared scripts

# Copy the right scripts folder according to PURPOSE. Defaults to slave scripts.
ARG PURPOSE
COPY scripts\_$PURPOSE scripts

# Currently, Bro stores logs in pwd when started.
WORKDIR /usr/local/bro/logs

ENV PATH=/usr/local/bro/bin:$PATH

ENV BROPATH=.:/usr/local/bro/share/bro:/usr/local/bro/share/bro/policy:/usr/local/bro/share/bro/site

# -C do not checksum request validity (docker foo!)
ENTRYPOINT ["bro", "-Q", "-C", "-i", "eth0", "/bro/scripts/"]
