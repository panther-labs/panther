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

# Clean up
rm -rf "${TMP_DIR}"
