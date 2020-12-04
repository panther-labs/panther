package customlogs

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
	"bufio"
	"os"

	jsoniter "github.com/json-iterator/go"
	"go.uber.org/zap"
)

type InferOpts struct {
	File *string
}

func Upload(logger *zap.SugaredLogger, opts *InferOpts) error {
	fd, err := os.Open(*opts.File)
	if err != nil {
		return err
	}
	defer fd.Close()

	scanner := bufio.NewScanner(fd)

	for scanner.Scan() {
		line := scanner.Bytes()
		var json map[string]interface{}
		err := jsoniter.Unmarshal(line, json)
		if err != nil {
			logger.Fatalf("failed to parse line as JSON")
		}
	}
	if err := scanner.Err(); err != nil {
		logger.Fatalf("failed")
	}

	return nil
}

type sampleEvent struct {
}
