package main

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2020 Panther Labs Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import (
	"flag"
	"log"
	"time"

	"github.com/panther-labs/panther/cmd/devtools/loadgen/filegen/logtype"
)

var (
	BUCKET = flag.String("bucket", "", "The bucket to write to.")
)

func main() {
	flag.Parse()

	if *BUCKET == "" {
		log.Fatal("-bucket not set")
	}

	numFiles := 100
	rowsPerFile := 1000
	s3gen := logtype.NewAWSS3ServerAccess(rowsPerFile)
	for i := 0; i < numFiles; i++ {
		uploadFile(s3gen.NewFile(time.Now().UTC()))
	}
}

func uploadFile(data []byte) {

}
