// Package unbox provides unboxing helpers for scalar values
package unbox

// All helpers are inlined and return the zero value if the pointer is nil

func String(s *string) string {
	if s != nil {
		return *s
	}
	return ""
}
func Int(n *int) int {
	if n != nil {
		return *n
	}
	return 0
}

func Int8(n *int8) int8 {
	if n != nil {
		return *n
	}
	return 0
}

func Int16(n *int16) int16 {
	if n != nil {
		return *n
	}
	return 0
}
func Int32(n *int32) int32 {
	if n != nil {
		return *n
	}
	return 0
}
func Int64(n *int64) int64 {
	if n != nil {
		return *n
	}
	return 0
}
func Uint(n *uint) uint {
	if n != nil {
		return *n
	}
	return 0
}
func Uint8(n *uint8) uint8 {
	if n != nil {
		return *n
	}
	return 0
}
func Uint16(n *uint16) uint16 {
	if n != nil {
		return *n
	}
	return 0
}
func Uint32(n *uint32) uint32 {
	if n != nil {
		return *n
	}
	return 0
}
func Uint64(n *uint64) uint64 {
	if n != nil {
		return *n
	}
	return 0
}

func Bool(b *bool) bool {
	if b != nil {
		return *b
	}
	return false
}

func Byte(b *byte) byte {
	if b != nil {
		return *b
	}
	return 0
}
