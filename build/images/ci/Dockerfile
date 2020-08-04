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

FROM buildpack-deps:buster-scm

LABEL description="An image that contains the necessary build tools to build panther"

ENV PYTHON_VERSION="3.7.7"
ENV GOLANG_VERSION="1.14.3"
ENV NODE_VERSION="12.17.0"

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
            amd64) goRelArch='linux-amd64'; goRelSha256='1c39eac4ae95781b066c144c58e45d6859652247f7515f0d2cba7be7d57d2226' ;; \
            armhf) goRelArch='linux-armv6l'; goRelSha256='b1c3a648c3c8877b98dfba1996dec604c8fb8899db07994b2dfd47b0063367c8' ;; \
            arm64) goRelArch='linux-arm64'; goRelSha256='a7a593e2ee079d83a1943edcd1c9ed2dae7529666fce04de8c142fb61c7cdd3e' ;; \
            i386) goRelArch='linux-386'; goRelSha256='46f8c744788103e8aeceb12c7d71eb16a58fe43e7e4711055fa9ef4bae50bff7' ;; \
            ppc64el) goRelArch='linux-ppc64le'; goRelSha256='329359e2b72839696e78b6c0a96fd939e28e7435d852f31107f68037dd5f7442' ;; \
            s390x) goRelArch='linux-s390x'; goRelSha256='1aad312fc7fa85d663e8226237cc7519b2599b88a213098abc10de8e84d6cfab' ;; \
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
        libreadline-gplv2-dev \
        libncursesw5-dev \
        libssl-dev \
        libsqlite3-dev \
        libgdbm-dev \
        libffi-dev \
        zlib1g-dev \
        libnss3-dev

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


