package tcodec

import (
	"strings"
	"time"
)

type Option interface {
	apply(ext *Extension)
}
type fnOption func(ext *Extension)

func (fn fnOption) apply(ext *Extension) {
	fn(ext)
}

func OverrideEncoder(enc TimeEncoder) Option {
	return fnOption(func(ext *Extension) {
		ext.override.encode = resolveEncodeFunc(enc)
	})
}

func OverrideDecoder(dec TimeDecoder) Option {
	return fnOption(func(ext *Extension) {
		ext.override.decode = resolveDecodeFunc(dec)
	})
}

func OverrideLocation(loc *time.Location) Option {
	return fnOption(func(ext *Extension) {
		ext.loc = loc
	})
}

// DefaultTagName is the struct tag name used for defining time decoders for a time.Time field.
const DefaultTagName = "tcodec"

func TagName(tagName string) Option {
	tagName = strings.TrimSpace(tagName)
	if tagName == "" {
		tagName = DefaultTagName
	}
	return fnOption(func(ext *Extension) {
		ext.tagName = tagName
	})
}
