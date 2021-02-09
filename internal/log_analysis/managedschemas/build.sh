#!/usr/bin/env bash

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

set -euxo pipefail

# This script should be used to update the embedded managed schema manifest release.
# Each version of Panther is bound to a minimum version of the `panther-analysis` repo.
# To avoid broken deployments due to GitHub outage or API limits, we embed the manifest of that release in the go code.
# This allows the custom resource that handles the managed schema updates to not rely on GitHub availability.
# Upon deployment, the custom resource handler will ensure all managed schemas are updated to at least this version.

# The script requires a single argument that is the tag of the minimum required version on the panther-analysis repo.
# When we want to update the minimum release version we should:
# - cd into this directory
# - run `./build.sh vX.Y.Z` to clone the tag, build the manifest and embed it using `go-bindata`
# - add the changed files (release_asset.go and release.go) and commit the changes
# - make a PR for the update

# Use first argument as release tag
RELEASE_TAG="$1"
PKG_NAME="managedschemas"

# Temporary directory (cleaned up at the end)
TMP_DIR="$(mktemp -d)"

# Shallow clone of panther-analysis repository
REPO_URL="https://github.com/panther-labs/panther-analysis.git"
git clone "${REPO_URL}" \
  --depth 1 \
  --branch "$RELEASE_TAG" \
  "${TMP_DIR}"


# Build manifest.yml by concatenating all schema/**/*.yml files
make -C "${TMP_DIR}" managed-schemas

# Embed manifest.yml into release_asset.go
go run github.com/go-bindata/go-bindata/go-bindata \
  -pkg "${PKG_NAME}" \
  -nometadata \
  -o "release_asset.go" \
  -prefix "${TMP_DIR}/dist/managed-schemas/" \
  "${TMP_DIR}/dist/managed-schemas/manifest.yml"

# Update ReleaseVersion variable in release.go
cat <<EOF > "release.go"
// Code generated for package $PKG_NAME by build.sh DO NOT EDIT. (@generated)
package $PKG_NAME

const ReleaseVersion = "${RELEASE_TAG}"

EOF
