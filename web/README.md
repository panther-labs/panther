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
npm run start
```

and a development server will be setup for you. Visit [localhost:8080](http://localhost:8080) in
order to view it.

### Deployment

This package shouldn't have to be deployed individually, since its deployment is part
of `mage deploy` which exposes a publicly available URL for you to access the UI.

There are situations though that may force you to have a local deployment (e.g. firewall restrictions)
of the Panther interface. To do that, all you need to do is build the web project and then serve its HTML through
a lightweight web server. Run:

```
npm run build
npm run serve
```

and visit [localhost:8080](http://localhost:8080) to view it.

Alternatively, if you have already ran `mage deploy` once in your account, you can
use docker to spin-up a container that will serve the image that was built during the last deployment. Remember that
this image has the built code of latest deployment and won't be able to showcase any source changes you have
not yet deployed. To do that, run:

```
docker run -e SERVER_PORT=8080 -p 8080:8080 {AWS_ACCOUNT_ID}.dkr.ecr.{AWS_REGION}.amazonaws.com/panther-web
```

replacing the variable `AWS_ACCOUNT_ID` and `AWS_REGION` with your account-id and the region that
panther is deployed.

### Testing

TODO
