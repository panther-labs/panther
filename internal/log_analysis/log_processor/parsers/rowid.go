package parsers

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
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"net"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
	"go.uber.org/zap"
)

// This is meant to be use in a Lambda by a single executing process. The state is fundamentally global.

const (
	nodeIDSize     = 6 // size of mac addr (bytes)
	rowCounterSize = 8 // (bytes)
	timeOffsetSize = 8 // (bytes)
)

var (
	nodeID [nodeIDSize]byte // mac addr of lambda to use as unique id for host

	// create a time basis relative to rowEpoch to decrease needed number of bits
	rowEpoch   = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)                  // NEVER CHANGE THIS!
	timeOffset = (uint64)(time.Now().UTC().Sub(rowEpoch).Nanoseconds()) / 100 // 0.1 milliseconds resolution
)

type RowID uint64

// NewRowID returns a unique row id name spaced as nodeID + timeOffset + rowCounter
func (rid *RowID) NewRowID() string {
	// the timeOffset and rowCounter are VarInt (https://developers.google.com/protocol-buffers/docs/encoding) encoded to reduce space
	newCounter := atomic.AddUint64((*uint64)(rid), 1)            // incr
	id := make([]byte, nodeIDSize+timeOffsetSize+rowCounterSize) // worse case size
	copy(id[:], nodeID[:])                                       // no encoding
	timeOffsetN := binary.PutUvarint(id[nodeIDSize:], timeOffset)
	rowCounterN := binary.PutUvarint(id[nodeIDSize+timeOffsetN:], newCounter)
	return hex.EncodeToString(id[:nodeIDSize+timeOffsetN+rowCounterN])
}

// ParseRowID extracts components of a row id
func ParseRowID(hexID string) (node [nodeIDSize]byte, offset, counter uint64, err error) {
	id, err := hex.DecodeString(hexID)
	if err != nil {
		return
	}
	copy(node[:], id[:nodeIDSize])
	offset, timeOffsetN := binary.Uvarint(id[nodeIDSize:])
	counter, _ = binary.Uvarint(id[nodeIDSize+timeOffsetN:])
	return
}

func init() {
	// get nodeID
	ifName, addr := getHardwareInterface()
	if ifName == "" { // should never happen ... but just in case
		err := errors.Errorf("Could not find hardware interface") // to get stacktrace
		zap.L().Error(err.Error(), zap.Error(err))
		noise := make([]byte, nodeIDSize)
		rand.Read(noise) // nolint (errcheck) , not checking error because there is noting else to do
		copy(nodeID[:], noise)
	} else {
		zap.L().Debug("Found hardware interface",
			zap.String("ifName", ifName),
			zap.String("addr", hex.EncodeToString(addr)))
		copy(nodeID[:], addr)
	}
}

// return first mac addr found
func getHardwareInterface() (string, []byte) {
	var err error
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", nil
	}

	for _, ifs := range interfaces {
		if len(ifs.HardwareAddr) >= nodeIDSize {
			return ifs.Name, ifs.HardwareAddr
		}
	}
	return "", nil
}
