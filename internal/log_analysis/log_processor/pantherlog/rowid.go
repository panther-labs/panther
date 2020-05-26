package pantherlog

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
	rowEpoch   = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)                   // NEVER CHANGE THIS!
	timeOffset = (uint64)(time.Now().UTC().Sub(rowEpoch).Nanoseconds()) / 1000 // microseconds resolution

	prefix = make([]byte, nodeIDSize+timeOffsetSize) // holds precomputed prefix
)

func init() {
	// get nodeID to use in prefix of uuid
	nif, err := getHardwareInterface()
	if err != nil { // should never happen ... but just in case
		zap.L().Error("Could not find hardware interface, generating random addr for uuid prefix", zap.Error(err))
		noise := make([]byte, nodeIDSize)
		_, _ = rand.Read(noise) // nolint (errcheck) , not checking error because there is noting else to do
		copy(nodeID[:], noise)
	} else {
		zap.L().Debug("Found hardware interface for uuid prefix",
			zap.String("ifName", nif.Name),
			zap.String("addr", hex.EncodeToString(nif.HardwareAddr)))
		copy(nodeID[:], nif.HardwareAddr)
	}

	// compute prefix
	copy(prefix[:], nodeID[:])                                        // no encoding
	timeOffsetN := binary.PutUvarint(prefix[nodeIDSize:], timeOffset) // VarInt encoding
	prefix = prefix[:nodeIDSize+timeOffsetN]                          // clip
}

type RowID uint64

// NewRowID returns a unique row id as a hex string, name spaced as nodeID + timeOffset + rowCounter
func (rid *RowID) NewRowID() string {
	// the timeOffset and rowCounter are VarInt (https://developers.google.com/protocol-buffers/docs/encoding) encoded to reduce space
	newCounter := atomic.AddUint64((*uint64)(rid), 1)              // incr
	id := make([]byte, len(prefix)+rowCounterSize)                 // worse case size
	copy(id[:], prefix)                                            // copy fixed prefix
	rowCounterN := binary.PutUvarint(id[len(prefix):], newCounter) // add counter to end Varint encoded
	return hex.EncodeToString(id[:len(prefix)+rowCounterN])
}

// return first mac addr found
func getHardwareInterface() (net.Interface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return net.Interface{}, err
	}

	for _, nif := range interfaces {
		if len(nif.HardwareAddr) >= nodeIDSize {
			return nif, nil
		}
	}
	return net.Interface{}, errors.Errorf("no valid interface found")
}

var nextRowID RowID

// NextRowID returns the next row id from a package-wide id generator.
func NextRowID() string {
	return nextRowID.NewRowID()
}
