package testdata

/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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
	"crypto/md5"
	"crypto/sha256"
	"io/ioutil"
	"testing"
)

const path = "../../../deployments/bootstrap.yml"

func BenchmarkMd5(b *testing.B) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		panic(err)
	}

	hash := md5.Sum(data)
	for i := 0; i < b.N; i++ {
		if md5.Sum(data) != hash {
			panic("not the same")
		}
	}
}

func BenchmarkSha256(b *testing.B) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		panic(err)
	}

	hash := sha256.Sum256(data)
	for i := 0; i < b.N; i++ {
		if sha256.Sum256(data) != hash {
			panic("not the same")
		}
	}
}

func BenchmarkSha224(b *testing.B) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		panic(err)
	}

	hash := sha256.Sum224(data)
	for i := 0; i < b.N; i++ {
		if sha256.Sum224(data) != hash {
			panic("not the same")
		}
	}
}
