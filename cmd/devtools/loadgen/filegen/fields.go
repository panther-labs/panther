package filegen

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
	"fmt"
	"math/rand"

	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/dchest/uniuri"
)

func String(n int) string {
	return uniuri.NewLen(n)
}

func Int16() int16 {
	return int16(rand.Int31() >> 16) // nolint (gosec)
}

func Int32() int32 {
	return rand.Int31() // nolint (gosec)
}

func Int64() int64 {
	return rand.Int63() // nolint (gosec)
}

func Int() int {
	return int(Int32())
}

func Unt16() uint16 {
	return uint16(rand.Uint32() >> 16) // nolint (gosec)
}

func Uint32() uint32 {
	return rand.Uint32() // nolint (gosec)
}

func Uint64() uint64 {
	return rand.Uint64() // nolint (gosec)
}

func AWSAccountID() string {
	return fmt.Sprintf("%012d", Uint32())[0:12]
}

func ARN(n int) string {
	return arn.ARN{
		Partition: "aws",
		Service:   String(8),
		Region:    "us-east-1",
		AccountID: AWSAccountID(),
		Resource:  String(15),
	}.String()
}

func IP() string {
	base := rand.Int31n(255) // nolint (gosec)
	return fmt.Sprintf("%d.%d.%d.%d", base, base+1, base+2, base+3)
}
