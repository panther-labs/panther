# Panther Front-end Application

Dashboard UI for Panther

> Due to multiple package management, please consider the project root as the current working directory
> for the following document sections

### Intro

To setup the project all you need to do is install its dependencies by running:

```
$ npm i
```

### Development

In order to develop locally, you must first have the project deployed on your AWS account. If you've successfully done that,
then a `.env.aws` file will be present in the `/out` directory, which holds the ENV vars that
are needed for local development. With this file present in `/out/.env.aws`, all you need to do is run (from the panther root directory):

```
$ npm run start
```

and a development server will be setup for you. Visit [localhost:8080](http://localhost:8080) in
order to view it.

### Deployment

This package shouldn't have to be deployed individually, since its deployment is part
of `mage deploy` which exposes a publicly available URL for you to access the UI.

There are situations though that may force you to have a local deployment (e.g. firewall restrictions)
of the Panther interface. To achieve that, you can either utilize the prebuilt docker image or create
a local build yourself. We will present both options in the sections below.

#### Custom Deployment using Docker

Having checked out the source code, from the project root directory, run the following:

```
$ docker build --file deployments/Dockerfile -t panther-web .
$ docker run --env-file out/.env.aws -e SERVER_PORT=8080 -p 8080:8080 panther-web
```

The command above will build the image and then run a container with it, by supplying:

- The AWS-related ENV vars as read from `.env.aws`
- A Panther version as described by the current commit
- The server port that the server will run on

Visit [localhost:8080](http://localhost:8080) to view it.

#### Custom Deployment without using Docker

If Docker is not your style, you can manually build the web project and then manually run the nodeJS
script that creates the server. To achieve that:

```
$ npm i
$ npm run build
```

Then make sure that all the contents of `out/.env.aws` are added as ENV vars in the shell that
the NodeJS process will run. You can add them in any way you prefer (manually, through bash_profile, etc.).
After that, simply run:

```
$ npm run serve
```

and visit [localhost:8080](http://localhost:8080) to view it.

### Testing

Running our front-end testing suite is as simple as running:

```
$ npm run test
```

If you want to watch for file changes & have the runner re-run the affected tests on every change, then run:

```
$ npm run test:watch
```
