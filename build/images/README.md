# Panther Docker Images

This folder holds the Dockerfiles for all of the publicly available Panther Docker images, found
under https://hub.docker.com/repository/docker/pantherlabs/. Currently, it's home to:

- [panther-buildpack](https://hub.docker.com/repository/docker/pantherlabs/panther-buildpack)

Containing the installations for Python, Golang & NodeJS that Panther needs in order to run, as well
as mage. This is mainly used by CI environments that want to be able to setup Panther in a machine
without a need to develop or deploy it to their AWS accounts

- [panther-development-pack](https://hub.docker.com/repository/docker/pantherlabs/panther-development-pack)

Containing all of the above, including Docker Engine & AWS SDK. This mainly used by actors who want
to deploy Panther & contribute to its development.

## Updating Panther Images

To update a Panther image you need to:

- build it locally
- tag it
- push the updated tags to the remote

This is not handled by any automation. This is something that needs to be done manually

## Building an image

To produce a local image out of a Dockerfile, make sure that Docker is running and type:

```
docker build -f {PATH_TO_DOCKERFILE} -t {IMAGE_NAME}:{TAG} .
```

In the above command:

- `-f` points to the dockerfile that describes what the image will build
- `-t` gives the image a tag. Although, you can give whatever tag you want, it's typical for image
  tags to follow the name under which they will be remotely stored in Dockerhub.
- `.` is the last param which adds the file context for the docker build. It describes the dir that
  docker will have access to during the build.

An example of that would be:

```
docker build -f build/images/deployment/Dockerfile -t pantherlabs/panther-development-pack:1.15.0 .
```

which will produce the image `pantherlabs/panther-development-pack:1.15.0` in your local machine. Typically,
the `IMAGE_NAME` should be `{ORGANIZATION}/${NAME}` to mimic the way it will be remotely stored in Dockerhub.

## Tagging an image

In the previous command the `-t` flag was just a tag. We could just as easily have written:

```
docker build -f build/images/deployment/Dockerfile -t mickey_mouse .
```

and the image `mickey_mouse` would have been locally created. Typically, whenever we build a new version
of an image, we also want to tag it as the `latest` one. Beware! The tag `latest` doesn't actually mean
"most recent". It's just another tag that's used by convention where, although people expect it to be the "more recent",
docker **doesn't enforce that** in any way.

If we want to tag an existing image we use the following command:

`docker tag {REPO_NAME}/{IMAGE_NAME}:{EXISTING_LOCAL_VERSION} {REPO_NAME}/{IMAGE_NAME}:{DESIRED_VERSION}`

For example, if we want to tag a new local image as `latest`, we write:

```
docker tag pantherlabs/panther-development-pack:1.15.0 pantherlabs/panther-development-pack:latest
```

> We could have also done that during build by specifying multiple `-t` params. For example,
> we could have written `docker build -t {IMAGE_NAME}:{TAG1} -t {IMAGE_NAME}:{TAG2} .`

## Deploying an image

To deploy an image you first need to be connected to Dockerhub. To do that, type:

```
docker login
```

and fill in your Dockerhub credentials.

With that being satisfied, pushing a new image is as simple as:

```
docker push {IMAGE_NAME}:{TAG} {IMAGE_NAME}:{TAG}
```

which mimics the way `git` works, where you push a local branch to a remote one. Just like `git`,
branches don't need to match in name, but it's a convention that they should. If they do match, the
above command can be simplified like so:

```
docker push {IMAGE_NAME}:{TAG}
```

In case an image has multiple tags, you can automatically push all of its tags by not specifying any
`TAG` during the push, like so:

```
docker push ${IMAGE_NAME}
```

For example, the following command pushes all tags of the image `pantherlabs/panther-development-pack`
to the remote `pantherlabs/panther-development-pack`:

```
docker push pantherlabs/panther-development-pack
```

## E2E example

In the following example, we will build a new image version, tag it as latest and push it to dockerhub:

```
docker build -f build/images/deployment/Dockerfile -t pantherlabs/panther-development-pack:1.15.0 -t pantherlabs/panther-development-pack:latest .
docker push pantherlabs/panther-development-pack
```
