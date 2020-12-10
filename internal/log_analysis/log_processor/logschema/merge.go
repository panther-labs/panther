package logschema

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

// Merge merges to value schemas to a a common schema that can handle both values.
// The returned value is a fully independent ValueSchema (deep copy).
// It panics if values a or b are not fully resolved via `Resolve().
func Merge(a, b *ValueSchema) *ValueSchema {
	if a == nil && b == nil {
		return nil
	}
	if a == nil {
		return b.Clone()
	}
	if b == nil {
		return a.Clone()
	}
	if a.Type == TypeRef || b.Type == TypeRef {
		panic("cannot merge unresolved values")
	}
	if a.Type == b.Type {
		switch a.Type {
		case TypeObject:
			return &ValueSchema{
				Type:   TypeObject,
				Fields: mergeObjectFields(a.Fields, b.Fields),
			}
		case TypeArray:
			return &ValueSchema{
				Type:    TypeArray,
				Element: Merge(a.Element, b.Element),
			}
		case TypeString:
			// Try to preserve indicators.
			// Make sure that indicators in the output value are a copy of the input slice.
			if indicators, _, changed := diffIndicators(a.Indicators, b.Indicators); !changed {
				return &ValueSchema{
					Type:       TypeString,
					Indicators: indicators,
				}
			}
			return &ValueSchema{Type: TypeString}
		case TypeTimestamp:
			if a.TimeFormat != b.TimeFormat {
				return &ValueSchema{Type: TypeString}
			}
			return &ValueSchema{
				Type:        TypeTimestamp,
				TimeFormat:  a.TimeFormat,
				IsEventTime: a.IsEventTime || b.IsEventTime, // event time should be 'sticky'
			}
		default:
			return &ValueSchema{
				Type: a.Type,
			}
		}
	}
	// We need to convert from one type to another.

	// The order of cases is important!
	// Each castX function only handles the 'lesser' value types in the following order
	// JSON > OBJECT,ARRAY > TIMESTAMP > STRING > FLOAT > BIGINT > INT
	switch {
	case a.Type.IsComposite(), b.Type.IsComposite():
		return &ValueSchema{Type: TypeJSON}
	case a.Type == TypeTimestamp:
		return castTimestamp(b.Type, a.TimeFormat, a.IsEventTime)
	case b.Type == TypeTimestamp:
		return castTimestamp(a.Type, b.TimeFormat, b.IsEventTime)
	case a.Type == TypeString, b.Type == TypeString:
		return &ValueSchema{Type: TypeString}
	case a.Type == TypeFloat:
		return castFloat(b.Type)
	case b.Type == TypeFloat:
		return castFloat(a.Type)
	case a.Type == TypeBigInt:
		return castBigInt(b.Type)
	case b.Type == TypeBigInt:
		return castBigInt(a.Type)
	case a.Type == TypeInt:
		return castInt(b.Type)
	case b.Type == TypeInt:
		return castInt(a.Type)
	default:
		return &ValueSchema{Type: TypeString}
	}
}

func mergeObjectFields(a, b []FieldSchema) (fields []FieldSchema) {
	for _, d := range DiffFields(a, b) {
		A, B := d.A, d.B
		switch {
		case A != nil && B != nil:
			val := Merge(&A.ValueSchema, &B.ValueSchema)
			fields = append(fields, FieldSchema{
				Name:        A.Name,
				Required:    A.Required && B.Required, // A field will only be required if it was found every time.
				ValueSchema: *val,
			})
		case A != nil:
			A.Required = false // Field was missing
			fields = append(fields, *A)
		case B != nil:
			B.Required = false // Field was missing
			fields = append(fields, *B)
		}
	}
	return fields
}

// castTimestamp handles values conversion for timestamps
// a is always type timestamp
// b is a 'lesser' value type (string, numeric, bool)
func castTimestamp(typ ValueType, timeFormat string, isEventTime bool) *ValueSchema {
	switch typ {
	case TypeBigInt:
		switch timeFormat {
		case "unix", "unix_ms", "unix_us", "unix_ns":
			// Preserve time format as this is something we cannot infer
			return &ValueSchema{
				Type:        TypeTimestamp,
				TimeFormat:  timeFormat,
				IsEventTime: isEventTime,
			}
		}
	case TypeFloat:
		switch timeFormat {
		case "unix":
			// Preserve time format as this is something we cannot infer
			// Floats can only be used for unix timestamps and fractional part is less than second
			return &ValueSchema{
				Type:        TypeTimestamp,
				TimeFormat:  "unix",
				IsEventTime: isEventTime,
			}
		case "unix_ms", "unix_us", "unix_ns":
			// Preserve time number format
			return &ValueSchema{
				Type: TypeFloat,
			}
		}
	}
	// Fallback to string
	return &ValueSchema{Type: TypeString}
}

// castBigInt handles values conversion for int64 values
// b is a 'lesser' value type (int, smallint, bool)
func castBigInt(typ ValueType) *ValueSchema {
	switch typ {
	case TypeInt, TypeSmallInt:
		return &ValueSchema{Type: TypeBigInt}
	default:
		return &ValueSchema{Type: TypeString}
	}
}

// castFloat handles values conversion for floats
// b is a 'lesser' value type (bigint, int, smallint, bool)
func castFloat(typ ValueType) *ValueSchema {
	switch typ {
	case TypeBigInt, TypeInt, TypeSmallInt:
		return &ValueSchema{Type: TypeFloat}
	default:
		return &ValueSchema{Type: TypeString}
	}
}

// castInt handles values conversion for integers
// b is a 'lesser' value type (smallint, bool)
func castInt(typ ValueType) *ValueSchema {
	switch typ {
	case TypeSmallInt:
		return &ValueSchema{Type: TypeInt}
	default:
		return &ValueSchema{Type: TypeString}
	}
}
