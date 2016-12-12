FROM debian:stretch

RUN apt-get update && \
	apt-get upgrade -y

RUN apt-get install -y \
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

# use correct branches / submodules
RUN git checkout topic/mfischer/deep-cluster && \
	git submodule update && \
	cd aux/broker && \
	git checkout topic/mfischer/broker-multihop && \
	cd ../..

RUN ./configure
RUN make -j4 install

WORKDIR /bro

# the auto_event.bro needs this port:
EXPOSE 9999

COPY config/etc /usr/local/bro/etc

COPY custom_scripts custom_scripts 

# Currently, Bro stores logs in pwd when started. 
WORKDIR /usr/local/bro/logs

# in here is currently only the auto_event bro, which blocks until it receives sth via a broker-client
# if it would not block, the container would exit immediately.
CMD ["/usr/local/bro/bin/bro", "-Q", "/bro/custom_scripts"]
