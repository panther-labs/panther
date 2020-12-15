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
#     pantherlabs/panther-buildpack:1.15.0
#
# When updating, bump the tag to the upcoming panther release.

FROM buildpack-deps:buster-scm

LABEL description="Panther CircleCI combined Go/Node/Python environment"

ENV GO_VERSION=1.15.5 NODE_VERSION=14.15.1 PYTHON_VERSION=3.7.9


# ****************     APT Packages     *******************
# NOTE: To keep the image as small as possible, always remove temp files and libraries we don't need.
RUN apt-get update && \
    apt-get purge -y \
        mercurial \
        python \
        python2 \
        python2.7 \
        subversion && \
    apt-get full-upgrade -y && \
    apt-get install -y --no-install-recommends \
        # Common
        make \
        unzip \
        xz-utils \
        # CGO
        g++ \
        libc6-dev && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*


# ****************     GO     *******************
# Based on https://github.com/CircleCI-Public/cimg-go/blob/master/1.15/Dockerfile

ENV GOPATH=/go PATH=/go/bin:/usr/local/go/bin:$PATH
RUN curl -sSL "https://golang.org/dl/go${GO_VERSION}.linux-amd64.tar.gz" | tar -xz -C /usr/local && \
    mkdir -p ${GOPATH}/src ${GOPATH}/bin && \
    go version && \
    # Install mage (magefile.org)
    go get -u -d github.com/magefile/mage && \
    cd $GOPATH/src/github.com/magefile/mage && \
    go run bootstrap.go && \
    rm -r $GOPATH/src/* && \
    # mage has a high UID, revert it back to root ownership (https://circleci.com/docs/2.0/high-uid-error)
    chown -R root:root ${GOPATH}/bin && \
    chmod -R 755 ${GOPATH}/bin && \
    mage -version


# ****************     NODE JS     *******************
# Based on https://github.com/CircleCI-Public/cimg-node/blob/master/12.18/Dockerfile
RUN curl -L -o node.tar.xz "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz" && \
    tar -xJf node.tar.xz -C /usr/local --strip-components=1 && \
    rm node.tar.xz && \
    ln -s /usr/local/bin/node /usr/local/bin/nodejs && \
    echo "node version: `node --version`" && \
    echo "npm version: `npm -version`"


# ****************     PYTHON     *******************
# Based on https://github.com/CircleCI-Public/cimg-python/blob/master/3.7/Dockerfile
ENV PYENV_ROOT=/home/circleci/.pyenv PATH=/home/circleci/.pyenv/shims:/home/circleci/.pyenv/bin:$PATH

RUN apt-get update && \
    # Install libraries needed to compile Python from source
    apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        libbz2-dev \
        liblzma-dev \
        libncurses5-dev \
        libncursesw5-dev \
        libreadline-dev \
        libffi-dev \
        libsqlite3-dev \
        libssl-dev \
        libxml2-dev \
        libxmlsec1-dev \
        llvm \
        python-openssl \
        tk-dev \
        zlib1g-dev && \
    # Build and install Python via pyenv
    curl https://pyenv.run | bash && \
    pyenv install ${PYTHON_VERSION} && pyenv global ${PYTHON_VERSION} && \
    python3 --version && \
    pip3 install --upgrade pip wheel && \
    # Purge build/dev libraries which are no longer needed
    apt-get purge -y \
        build-essential \
        libbz2-dev \
        liblzma-dev \
        libncurses5-dev \
        libncursesw5-dev \
        libreadline-dev \
        libffi-dev \
        libsqlite3-dev \
        libssl-dev \
        libxml2-dev \
        libxmlsec1-dev \
        llvm \
        tk-dev \
        zlib1g-dev && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
