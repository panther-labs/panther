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

AWS_PUBLIC_ACCOUNT_ID=349240696275
AWS_PUBLIC_ECR_REGION=us-west-2
IMAGE_REPO_NAME=panther-ui
PANTHER_VERSION=v0.1

echo Logging in to Amazon ECR...
$(aws ecr get-login --registry-ids $AWS_PUBLIC_ACCOUNT_ID --no-include-email --region $AWS_PUBLIC_ECR_REGION)
echo Build started on `date`
echo Building the Docker image...
docker build -t $IMAGE_REPO_NAME --build-arg PANTHER_VERSION=$PANTHER_VERSION .
docker tag $IMAGE_REPO_NAME $AWS_PUBLIC_ACCOUNT_ID.dkr.ecr.$AWS_PUBLIC_ECR_REGION.amazonaws.com/$IMAGE_REPO_NAME:latest
docker tag $IMAGE_REPO_NAME $AWS_PUBLIC_ACCOUNT_ID.dkr.ecr.$AWS_PUBLIC_ECR_REGION.amazonaws.com/$IMAGE_REPO_NAME:$PANTHER_VERSION
echo Build completed on `date`
echo Pushing the Docker image...
docker push $AWS_PUBLIC_ACCOUNT_ID.dkr.ecr.$AWS_PUBLIC_ECR_REGION.amazonaws.com/$IMAGE_REPO_NAME:latest
docker push $AWS_PUBLIC_ACCOUNT_ID.dkr.ecr.$AWS_PUBLIC_ECR_REGION.amazonaws.com/$IMAGE_REPO_NAME:$PANTHER_VERSION
echo Image uploaded on `date`
