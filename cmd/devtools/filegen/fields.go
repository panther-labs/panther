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
	fuzz "github.com/google/gofuzz"
	jsoniter "github.com/json-iterator/go"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
)

// functions to randomly generate data

func Bool() bool {
	return rand.Int31n(2) == 0 // nolint (gosec)
}

func String(n int) string {
	return uniuri.NewLen(n)
}

var alphaNumChars = []byte(`abcdedfhijklmnopqrstuvwxyz0123456789`)

func StringAlphaNum(n int) string {
	return uniuri.NewLenChars(n, alphaNumChars)
}

func StringSlice(n, m int) []string {
	slice := make([]string, m)
	for i := 0; i < m; i++ {
		slice[i] = String(n)
	}
	return slice
}

func StringChoice(choices []string) string {
	// Intn() returns [0,n)
	return choices[Intn(len(choices))] // nolint (gosec)
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

func Intn(n int) int {
	return int(rand.Int31n(int32(n))) // nolint (gosec)
}

func Uint16() uint16 {
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

func ARN() string {
	return arn.ARN{
		Partition: "aws",
		Service:   String(8),
		Region:    "us-east-1",
		AccountID: AWSAccountID(),
		Resource:  String(15),
	}.String()
}

func IP() string {
	base := rand.Int31n(256) // nolint (gosec)
	return fmt.Sprintf("%d.%d.%d.%d", base, base, base, base)
}

func RawMessage(atLeast, atMost int) pantherlog.RawMessage {
	f := fuzz.New().NilChance(0).NumElements(atLeast, atMost)
	message := make(map[string]string)
	f.Fuzz(&message)
	if len(message) == 0 {
		return []byte("null")
	}
	messageJSON, err := jsoniter.Marshal(message)
	if err != nil {
		panic(err)
	}
	return messageJSON
}

func ToPantherString(s string) pantherlog.String {
	return pantherlog.String{
		Value:  s,
		Exists: true,
	}
}

func ToPantherUint16(i uint16) pantherlog.Uint16 {
	return pantherlog.Uint16{
		Value:  i,
		Exists: true,
	}
}

func ToPantherInt32(i int32) pantherlog.Int32 {
	return pantherlog.Int32{
		Value:  i,
		Exists: true,
	}
}

func ToPantherInt64(i int64) pantherlog.Int64 {
	return pantherlog.Int64{
		Value:  i,
		Exists: true,
	}
}

func ToPantherBool(b bool) pantherlog.Bool {
	return pantherlog.Bool{
		Value:  b,
		Exists: true,
	}
}
