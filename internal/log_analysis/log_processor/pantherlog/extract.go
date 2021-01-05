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

import jsoniter "github.com/json-iterator/go"

func ExtractRawMessageIndicators(w ValueWriter, extractor func(ValueWriter, *jsoniter.Iterator, string), messages ...RawMessage) {
	var iter *jsoniter.Iterator
	for _, msg := range messages {
		if msg == nil {
			continue
		}
		if iter == nil {
			iter = jsoniter.ConfigDefault.BorrowIterator(msg)
		} else {
			iter.Error = nil
			iter.ResetBytes(msg)
		}
		extractor(w, iter, "")
	}
	if iter != nil {
		iter.Pool().ReturnIterator(iter)
	}
}
