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
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRowID(t *testing.T) {
	var rowIDCounter RowID // number of rows generated in this lambda execution
	for i := 0; i < 1000; i++ {
		id := rowIDCounter.NewRowID()
		extractedNodeID, extractedTimeOffset, extractedCounter, err := ParseRowID(id)
		require.NoError(t, err)
		assert.Equal(t, nodeID, extractedNodeID)
		assert.Equal(t, timeOffset, extractedTimeOffset)
		assert.Equal(t, (uint64)(i+1), extractedCounter)
	}
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
