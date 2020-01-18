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

# Can't use alpine due to some node_module deps
FROM node:13.2-alpine

LABEL description="The image that builds the web code and servers it through an express NodeJS server"

# Build argument for versioning
ARG PANTHER_VERSION


# Setup default ENV variables
ENV SERVER_PORT=8080
ENV NODE_ENV=production
ENV PANTHER_VERSION=$PANTHER_VERSION

# Update debian distro
RUN apk update && apk add --no-cache --update nasm libtool alpine-sdk autoconf automake

# Move all of our logic
RUN mkdir /code

# To a different folder so we don't pollute the root of our container
WORKDIR /code

# Mount the package.json
ADD package.json .

# Install the dependencies
RUN npm --production=false install

# Mount the code
ADD webpack.config.js tsconfig.json .babelrc ./
ADD web web

# Build the project with the ENV vars present in the system & run the node server
CMD npm run build-assets && npm run serve-assets

# through the port chosen during build time (defaults to 8080)
EXPOSE ${SERVER_PORT}

