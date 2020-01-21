#
# ****************     BUILD STAGE     *******************
#
FROM node:13.2-alpine AS build-env

LABEL description="The image that builds the web code and serves it through an express NodeJS server"

# Update debian distro
RUN apk update && apk add --no-cache --update nasm libtool alpine-sdk autoconf automake

# Move all of our logic
RUN mkdir /code

# To a different folder so we don't pollute the root of our container
WORKDIR /code

# Mount the package.json
ADD package.json package-lock.json ./

# Install the dependencies
RUN npm i

# Mount the necessary source code
ADD .babelrc tsconfig.json webpack.config.js .env ./
ADD enterprise enterprise
ADD web web

# Build argument & ENV var for versioning
ARG PANTHER_VERSION
ENV PANTHER_VERSION=$PANTHER_VERSION

# Convert NODE_ENV to production in order to adjust webpack configuration accordingly
ENV NODE_ENV=production

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
COPY --from=build-env /code/web/dist dist

# Add the script that runs the express server
ADD  web/scripts/serve.js scripts/serve.js

# Install express
RUN npm install express

# Run the express server to serve the assets
CMD node scripts/serve.js

# through the port chosen during build time (defaults to 8080)
EXPOSE ${SERVER_PORT}

