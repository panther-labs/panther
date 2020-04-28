# Panther is a Cloud-Native SIEM for the Modern Security Team.
# Copyright (C) 2020 Panther Labs Inc
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

FROM buildpack-deps:stretch-scm

LABEL description="An image that contains the necessary build tools to build panther"

ENV PYTHON_VERSION="3.7.7"
ENV GOLANG_VERSION="1.14.1"
ENV NODE_VERSION="12.16.1"

# ****************     GO     *******************
RUN apt-get update && apt-get install -y --no-install-recommends \
        g++ \
        gcc \
        libc6-dev \
        make \
        pkg-config \
        unzip \
	&& rm -rf /var/lib/apt/lists/*

# Depending on the CPU architecture of the latest stable debian stretch, pick which GO distribution
# should install and then download and unpack it
RUN set -eux \
    && dpkgArch="$(dpkg --print-architecture)" \
    && case "${dpkgArch##*-}" in \
            amd64) goRelArch='linux-amd64'; goRelSha256='2f49eb17ce8b48c680cdb166ffd7389702c0dec6effa090c324804a5cac8a7f8' ;; \
            armhf) goRelArch='linux-armv6l'; goRelSha256='04f10e345dae0d7c6c32ffd6356b47f2d4d0e8a0cb757f4ef48ead6c5bef206f' ;; \
            arm64) goRelArch='linux-arm64'; goRelSha256='5d8f2c202f35481617e24e63cca30c6afb1ec2585006c4a6ecf16c5f4928ab3c' ;; \
            i386) goRelArch='linux-386'; goRelSha256='92d465accdebbe2d0749b2f90c22ecb1fd2492435144923f88ce410cd56b6546' ;; \
            ppc64el) goRelArch='linux-ppc64le'; goRelSha256='6559201d452ee2782dfd684d59c05e3ecf789dc40a7ec0ad9ae2dd9f489c0fe1' ;; \
            s390x) goRelArch='linux-s390x'; goRelSha256='af009bd6e7729c441fec78af427743fefbf11f919c562e01b37836d835f74226' ;; \
    		*) echo >&2 "warning: current architecture ($dpkgArch) does not have a corresponding Go binary release"; exit 1 ;; \
    	esac \
    && wget -O go.tgz https://golang.org/dl/go${GOLANG_VERSION}.${goRelArch}.tar.gz \
    && echo "${goRelSha256} *go.tgz" | sha256sum -c - \
    && tar -C /usr/local -xzf go.tgz \
    && rm go.tgz

# Update global ENV variables
ENV GOPATH /go
ENV PATH="$GOPATH/bin:/usr/local/go/bin:$PATH"

# Install mage
RUN mkdir -p "$GOPATH/src" "$GOPATH/bin" && chmod -R 777 "$GOPATH"
RUN go get github.com/magefile/mage
# ****************     END GO     *******************



# ****************     PYTHON     *******************
RUN apt-get update && apt-get install -y \
        build-essential \
        checkinstall \
        libreadline-gplv2-dev \
        libncursesw5-dev \
        libssl-dev \
        libsqlite3-dev \
        tk-dev \
        libgdbm-dev \
        libc6-dev \
        libbz2-dev \
        libffi-dev \
        zlib1g-dev

# Download the chosen Python3 version, unpack and install it
RUN wget https://www.python.org/ftp/python/${PYTHON_VERSION%%[a-z]*}/Python-$PYTHON_VERSION.tar.xz \
    && tar xf Python-$PYTHON_VERSION.tar.xz \
    && cd ./Python-$PYTHON_VERSION \
    && ./configure \
    && make \
    && make install \
    && pip3 install --upgrade pip \
    && cd .. \
    && rm -rf Python-*
# ****************     END PYTHON     *******************



# ****************     NODE JS     *******************
RUN nPackageSrcDir="/usr/src/n" \
    && git clone https://github.com/tj/n $nPackageSrcDir \
    && cd $nPackageSrcDir \
    && make install \
    && n $NODE_VERSION \
    && cd / \
    && rm -rf $nPackageSrcDir
# ****************     END NODE JS     *******************


