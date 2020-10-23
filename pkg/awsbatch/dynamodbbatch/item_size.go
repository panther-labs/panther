package dynamodbbatch

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
	"github.com/aws/aws-sdk-go/service/dynamodb"
)

// GetDynamoItemSize calculates the size that dynamo considers the item to be
func GetDynamoItemSize(item map[string]*dynamodb.AttributeValue) int {
	itemSize := 0
	// One dynamo row size is the sum of the size of all the keys and values of that row
	for key, value := range item {
		itemSize += len(key)
		itemSize += getDynamoAttributeValueSize(value)
	}
	return itemSize
}

// getDynamoAttributeValueSize gets the size of a single dynamodb AttributeValue based on its type.
//
// reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/CapacityUnitCalculations.html
//
// I double checked a couple values by comparing against this calculator I found online:
// https://zaccharles.github.io/dynamodb-calculator/
// generally my estimates were within a hundred bytes for resources that were a few thousand bytes
// in size
func getDynamoAttributeValueSize(value *dynamodb.AttributeValue) int {
	if value.B != nil {
		return len(value.B)
	}
	// Lists have 3 bytes of overhead for the list, and 1 byte of overhead per element
	if value.L != nil {
		size := 3 + len(value.L)
		for _, nestedValue := range value.L {
			size += getDynamoAttributeValueSize(nestedValue)
		}
		return size
	}
	if value.S != nil {
		return len(*value.S)
	}
	// Maps have 3 bytes of overhead, plus 1 byte of overhead per key/value pair
	if value.M != nil {
		return 3 + GetDynamoItemSize(value.M) + len(value.M)
	}
	if value.BOOL != nil {
		return 1
	}
	if value.BS != nil {
		size := 0
		for _, binaryValue := range value.BS {
			size += len(binaryValue)
		}
		return size
	}
	// DynamoDB represents numbers as strings. They won't release exactly how to know how many bytes
	// a number takes up, but they say:
	//
	// "Numbers are variable length, with up to 38 significant digits. Leading and trailing zeroes
	// are trimmed. The size of a number is approximately
	// (length of attribute name) + (1 byte per two significant digits) + (1 byte)."
	//
	// There is an additional 1 byte of overhead for negative numbers.
	//
	// So to estimate that approximation, I just divide the length by 2 (to approximate significant
	// digits) and add 1.
	//
	// For odd numbers of significant digits, dynamo rounds up. That means a 7 digit number takes 4
	// bytes (7/2 = 3.5 round up to 4). Since we're returning an int, though, we would truncate this
	// to 3. To get around this, we always add .5 after dividing by 2. This means on odd digits such
	// as 7 we get 7/2 = 3.5 + .5 = 4 (the same number dynamo would get) and on event digits such as
	// 8 we get 8/2 = 4 = .5 = 4.5 cast to an integer = 4, which is again the correct value.
	if value.N != nil {
		overhead := 1.5
		if len(*value.N) > 0 && (*value.N)[0] == '-' {
			overhead++
		}
		return int(float64(len(*value.N))/2 + overhead)
	}
	if value.NS != nil {
		size := 0.0
		for _, number := range value.NS {
			if number != nil {
				overhead := 1.5
				if len(*number) > 0 && (*number)[0] == '-' {
					overhead++
				}
				size += float64(len(*number))/2 + overhead
			}
		}
		return int(size)
	}
	if value.NULL != nil {
		return 1
	}
	if value.SS != nil {
		size := 0
		for _, stringValue := range value.SS {
			if stringValue != nil {
				size += len(*stringValue)
			}
		}
		return size
	}
	return 0
}
