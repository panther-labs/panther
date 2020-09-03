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

# Published version:
#     pantherlabs/panther-buildpack:1.8.0

FROM buildpack-deps:buster-scm

LABEL description="An image that contains the necessary build tools to build panther"

ENV GOLANG_VERSION="1.15.1"
ENV NODE_VERSION="12.18.3"


# ****************     APT Packages     *******************
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        make \
        python3 \
        unzip \
	&& rm -rf /var/lib/apt/lists/*



# ****************     GO     *******************
# Depending on the CPU architecture of the latest stable debian stretch, pick which GO distribution
# should install and then download and unpack it
RUN set -eux \
    && dpkgArch="$(dpkg --print-architecture)" \
    && case "${dpkgArch##*-}" in \
            amd64) goRelArch='linux-amd64'; goRelSha256='70ac0dbf60a8ee9236f337ed0daa7a4c3b98f6186d4497826f68e97c0c0413f6' ;; \
            armhf) goRelArch='linux-armv6l'; goRelSha256='62db2fac55309f4bc1f73577165dcb331a4c649e39bdbe04943579e0b2b0c06e' ;; \
            arm64) goRelArch='linux-arm64'; goRelSha256='ca21c771d906fbba8840b3a4831b1aa118f6e09b5d028323592faba382787a03' ;; \
            i386) goRelArch='linux-386'; goRelSha256='7e0c8e9749be69c28d3333a81ce8386916ba1306b40476a43f7794dc309eaf4c' ;; \
            ppc64el) goRelArch='linux-ppc64le'; goRelSha256='50bdca87edc30bdc12956dab765c1b85249373a156a7a00eb998cdc70790fb94' ;; \
            s390x) goRelArch='linux-s390x'; goRelSha256='2c3823790fc5508bd53bb104e6cc0052d1892855546a0eae0ea7809c84160543' ;; \
    		*) echo >&2 "warning: current architecture ($dpkgArch) does not have a corresponding Go binary release"; exit 1 ;; \
    	esac \
    && wget --no-verbose -O go.tgz https://golang.org/dl/go${GOLANG_VERSION}.${goRelArch}.tar.gz \
    && echo "${goRelSha256} *go.tgz" | sha256sum -c - \
    && tar -C /usr/local -xzf go.tgz \
    && rm go.tgz

# Update global ENV variables
ENV GOPATH /go
ENV PATH="$GOPATH/bin:/usr/local/go/bin:$PATH"

# Install mage
RUN mkdir -p "$GOPATH/src" "$GOPATH/bin" && chmod -R 777 "$GOPATH"
RUN go get github.com/magefile/mage



# ****************     NODE JS     *******************
RUN nPackageSrcDir="/usr/src/n" \
    && git clone https://github.com/tj/n $nPackageSrcDir \
    && cd $nPackageSrcDir \
    && make install \
    && n $NODE_VERSION \
    && cd / \
    && rm -rf $nPackageSrcDir
