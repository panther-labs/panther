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
	"github.com/aws/aws-sdk-go/aws"
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
	// Lists have 3 bytes of overhead
	if value.L != nil {
		size := 3
		for _, nestedValue := range value.L {
			size += getDynamoAttributeValueSize(nestedValue)
		}
		return size
	}
	if value.S != nil {
		return len(aws.StringValue(value.S))
	}
	// Maps have 3 bytes of overhead
	if value.M != nil {
		return 3 + GetDynamoItemSize(value.M)
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
	// (length of attribute name) + (1 byte per two significant digits) + (1 byte).
	//
	// So to estimate that approximation, I just divide the length by 2 (to approximate significant
	// digits) and add 1.
	//
	// Additionally, dynamo rounds up on the significant digits / 2 math, so we add .5 then cast to
	// an int to round up
	if value.N != nil {
		return int(float64(len(aws.StringValue(value.N)))/2.0 + 1 + .5)
	}
	if value.NS != nil {
		size := 0.0
		for _, number := range value.NS {
			size += float64(len(aws.StringValue(number))/2) + 1 + .5
		}
		return int(size)
	}
	if value.NULL != nil {
		return 1
	}
	if value.SS != nil {
		size := 0
		for _, stringValue := range value.SS {
			size += len(aws.StringValue(stringValue))
		}
		return size
	}
	return 0
}
