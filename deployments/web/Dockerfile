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

#
# ****************     BUILD STAGE     *******************
#
FROM node:13.2-alpine AS build-env

LABEL description="The image that builds the web code and serves it through an express NodeJS server"

# Update debian distro
RUN apk update && apk add --no-cache --update git nasm libtool alpine-sdk autoconf automake

# Move all of our logic
RUN mkdir /code

# To a different folder so we don't pollute the root of our container
WORKDIR /code

# Mount the package.json
ADD package.json package-lock.json ./

# Install the dependencies
RUN npm i

# Mount the necessary source code
ADD .babelrc tsconfig.json webpack.config.js ./
ADD .git .git
ADD out/.env.aws out/.env.aws
ADD web web

# Build the project (additional ENV vars are read from a .env)
RUN npm run build

#
# ****************     DEPLOYMENT & SERVE STAGE     *******************
#
FROM node:13.2-alpine

# Setup default port for fallback. This variable will be overriden on runtime by the associated ECS service.
ENV SERVER_PORT=8080

# Make sure we add a folder to not pollute our root
RUN mkdir /code

# And make it the default WD
WORKDIR /code

# Copy the artifacts from the previous stage
COPY --from=build-env /code/web/dist web/dist

# Add the script that runs the express server
ADD package.json .
ADD  web/scripts web/scripts

# Install express
#
## WARNING: Be careful not to add the package.json, since it will install all of your dependencies
## even when you explicitly try to install a single one
#
RUN npm install express express-static-gzip

# Run the express server to serve the assets
CMD npm run serve

# through the port chosen during build time (defaults to 8080)
EXPOSE ${SERVER_PORT}

