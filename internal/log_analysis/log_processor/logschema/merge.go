package logschema

import "reflect"

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
	if a.Type != b.Type {
		return castValue(a, b)
	}
	switch a.Type {
	case TypeObject:
		var fields []FieldSchema
		for _, d := range DiffFields(a.Fields, b.Fields) {
			A, B := d.A, d.B
			switch {
			case A != nil && B != nil:
				val := Merge(&A.ValueSchema, &B.ValueSchema)
				fields = append(fields, FieldSchema{
					Name:        A.Name,
					Required:    A.Required && B.Required,
					ValueSchema: *val,
				})
			case A != nil:
				A.Required = false
				fields = append(fields, *A)
			case B != nil:
				B.Required = false
				fields = append(fields, *B)
			}
		}
		return &ValueSchema{
			Type:   TypeObject,
			Fields: fields,
		}
	case TypeArray:
		return &ValueSchema{
			Type:    TypeArray,
			Element: Merge(a.Element, b.Element),
		}
	case TypeString:
		// Try to preserve indicators
		if reflect.DeepEqual(a.Indicators, b.Indicators) {
			return a
		}
		return &ValueSchema{
			Type: TypeString,
		}
	default:
		return a
	}
}

// castValue handles merging values of different types while trying to preserve value information.
// This function assumes a.Type != b.Type
func castValue(a, b *ValueSchema) *ValueSchema {
	// The order of casts is important.
	// JSON > OBJECT,ARRAY > TIMESTAMP > STRING > FLOAT > BIGINT > INT
	// Each case in this switch statement preserves that order.
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
		return castFloat(a, b)
	case b.Type == TypeFloat:
		return castFloat(b, a)
	case a.Type == TypeBigInt:
		return castBigInt(a, b)
	case b.Type == TypeBigInt:
		return castBigInt(b, a)
	case a.Type == TypeInt:
		return castInt(a, b)
	case b.Type == TypeInt:
		return castInt(b, a)
	default:
		return &ValueSchema{Type: TypeString}
	}
}

func castTimestamp(a, b *ValueSchema) *ValueSchema {
	switch b.Type {
	case TypeBigInt:
		switch a.TimeFormat {
		case "unix", "unix_ms", "unix_us", "unix_ns":
			return a.Clone()
		}
	case TypeFloat:
		if a.TimeFormat == "unix" {
			return a.Clone()
		}
	}
	// Fallback to string
	return &ValueSchema{Type: TypeString}
}

func castBigInt(a, b *ValueSchema) *ValueSchema {
	switch b.Type {
	case TypeInt, TypeSmallInt:
		return a.Clone()
	default:
		return &ValueSchema{Type: TypeString}
	}
}

func castFloat(a, b *ValueSchema) *ValueSchema {
	switch b.Type {
	case TypeBigInt, TypeInt, TypeSmallInt:
		return a.Clone()
	default:
		return &ValueSchema{Type: TypeString}
	}
}

func castInt(a, b *ValueSchema) *ValueSchema {
	switch b.Type {
	case TypeSmallInt:
		return a.Clone()
	default:
		return &ValueSchema{Type: TypeString}
	}
}
