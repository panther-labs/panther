# Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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

ENV PYTHON_VERSION="3.7.4"
ENV GOLANG_VERSION="1.13.5"
ENV NODE_VERSION="12.14.0"

# ****************     GO     *******************
RUN apt-get update && apt-get install -y --no-install-recommends \
        g++ \
        gcc \
        libc6-dev \
        make \
        pkg-config \
	&& rm -rf /var/lib/apt/lists/*

# Depending on the CPU architecture of the latest stable debian stretch, pick which GO distribution
# should install and then download and unpack it
RUN set -eux \
    && dpkgArch="$(dpkg --print-architecture)" \
    && case "${dpkgArch##*-}" in \
    		amd64) goRelArch='linux-amd64'; goRelSha256='512103d7ad296467814a6e3f635631bd35574cab3369a97a323c9a585ccaa569' ;; \
    		armhf) goRelArch='linux-armv6l'; goRelSha256='26259f61d52ee2297b1e8feef3a0fc82144b666a2b95512402c31cc49713c133' ;; \
    		arm64) goRelArch='linux-arm64'; goRelSha256='227b718923e20c846460bbecddde9cb86bad73acc5fb6f8e1a96b81b5c84668b' ;; \
    		i386) goRelArch='linux-386'; goRelSha256='3b830fa25f79ab08b476f02c84ea4125f41296b074017b492ac1ff748cf1c7c9' ;; \
    		ppc64el) goRelArch='linux-ppc64le'; goRelSha256='292814a5ea42a6fc43e1d1ea61c01334e53959e7ab34de86eb5f6efa9742afb6' ;; \
    		s390x) goRelArch='linux-s390x'; goRelSha256='cfbb2959f243880abd1e2efd85d798b8d7ae4a502ab87c4b722c1bd3541e5dc3' ;; \
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


