package parsers

import (
	"strconv"
	"strings"
)

func CsvStringToPointer(value string) *string {
	if value == "-" {
		return nil
	}
	return &value
}

func CsvStringToIntPointer(value string) *int {
	if value == "-" {
		return nil
	}
	result, err := strconv.Atoi(value)
	if err != nil {
		return nil
	}
	return &result
}

func CsvStringToInt16Pointer(value string) *int16 {
	if value == "-" {
		return nil
	}
	result, err := strconv.ParseInt(value, 10, 16)
	if err != nil {
		return nil
	}
	returnValue := int16(result)
	return &returnValue
}

func CsvStringToFloat64Pointer(value string) *float64 {
	if value == "-" {
		return nil
	}
	result, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return nil
	}
	return &result
}

func CsvStringToArray(value string) []string {
	if value == "-" {
		return []string{}
	}

	return strings.Split(value, ",")
}
