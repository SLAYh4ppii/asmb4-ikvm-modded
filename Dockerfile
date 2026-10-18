FROM debian:9

RUN echo 'deb http://archive.debian.org/debian stretch main' > /etc/apt/sources.list \
 && echo 'Acquire::Check-Valid-Until false;' > /etc/apt/apt.conf.d/99archive \
 && apt-get -o Acquire::AllowInsecureRepositories=true update -qq \
 && apt-get install -y -qq --force-yes util-linux \
 && apt-get install -y -qq --force-yes python make \
 && apt-get install -y -qq --force-yes gcc-arm-linux-gnueabi qemu-user-static \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /work
