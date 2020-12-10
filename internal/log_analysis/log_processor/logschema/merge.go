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
// It panics if values a or b are not fully resolved via `Resolve().
func Merge(a, b *ValueSchema) *ValueSchema {
	if a == nil && b == nil {
		return nil
	}
	if a == nil {
		return b
	}
	if b == nil {
		return a
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
			// Try to preserve indicators
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
	case a.Type == TypeJSON, b.Type == TypeJSON,
		a.Type == TypeObject, b.Type == TypeObject,
		a.Type == TypeArray, b.Type == TypeArray:
		return &ValueSchema{Type: TypeJSON}
	case a.Type == TypeTimestamp:
		return castTimestamp(a, b)
	case b.Type == TypeTimestamp:
		return castTimestamp(b, a)
	case a.Type == TypeString, b.Type == TypeString:
		return &ValueSchema{Type: TypeString}
	case a.Type == TypeFloat:
		return castFloat(b)
	case b.Type == TypeFloat:
		return castFloat(a)
	case a.Type == TypeBigInt:
		return castBigInt(b)
	case b.Type == TypeBigInt:
		return castBigInt(a)
	case a.Type == TypeInt:
		return castInt(b)
	case b.Type == TypeInt:
		return castInt(a)
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

func castTimestamp(a, b *ValueSchema) *ValueSchema {
	switch b.Type {
	case TypeBigInt:
		switch a.TimeFormat {
		case "unix", "unix_ms", "unix_us", "unix_ns":
			return &ValueSchema{
				Type:        TypeTimestamp,
				TimeFormat:  a.TimeFormat,
				IsEventTime: a.IsEventTime,
			}
		}
	case TypeFloat:
		switch a.TimeFormat {
		case "unix":
			return &ValueSchema{
				Type:        TypeTimestamp,
				TimeFormat:  "unix",
				IsEventTime: a.IsEventTime,
			}
		case "unix_ms", "unix_us", "unix_ns":
			return &ValueSchema{
				Type: TypeFloat,
			}
		}
	}
	// Fallback to string
	return &ValueSchema{Type: TypeString}
}

func castBigInt(b *ValueSchema) *ValueSchema {
	switch b.Type {
	case TypeInt, TypeSmallInt:
		return &ValueSchema{Type: TypeBigInt}
	default:
		return &ValueSchema{Type: TypeString}
	}
}

func castFloat(b *ValueSchema) *ValueSchema {
	switch b.Type {
	case TypeBigInt, TypeInt, TypeSmallInt:
		return &ValueSchema{Type: TypeFloat}
	default:
		return &ValueSchema{Type: TypeString}
	}
}

func castInt(b *ValueSchema) *ValueSchema {
	switch b.Type {
	case TypeSmallInt:
		return &ValueSchema{Type: TypeInt}
	default:
		return &ValueSchema{Type: TypeString}
	}
}
