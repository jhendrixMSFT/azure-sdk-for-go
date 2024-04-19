//go:build go1.18
// +build go1.18

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package datetime

import (
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Format defines the possible date/time formats.
type Format int

const (
	FormatRFC3339  Format = 0
	FormatRFC1123  Format = 1
	FormatRFC7231  Format = 2
	FormatDateOnly Format = 3
	FormatTimeOnly Format = 4
	FormatUnix     Format = 5
)

// DateTime is a [time.Time] with specific formatting.
// Don't use this type directly, use [New] instead.
type DateTime struct {
	val time.Time
	fmt Format
}

// Options contains the optional values for creating a [DateTime].
type Options struct {
	// From is used to initialize [DateTime] from the specified [time.Time].
	From time.Time
}

// New creates a new [DateTime].
//   - format defines the string representation
//   - options contains the optional values
func New(format Format, options *Options) DateTime {
	dt := DateTime{
		fmt: format,
	}
	if options != nil {
		dt.val = options.From
	}
	return dt
}

func (d DateTime) MarshalJSON() ([]byte, error) {
	b := d.String()
	return []byte(`"` + b + `"`), nil
}

func (d DateTime) MarshalText() ([]byte, error) {
	return []byte(d.String()), nil
}

func (d *DateTime) UnmarshalJSON(data []byte) error {
	if data == nil || string(data) == "null" {
		// JSON null
		return nil
	}

	return d.unmarshal(data, `"`+getLayout(data, d.fmt)+`"`)
}

func (d *DateTime) UnmarshalText(data []byte) error {
	// this is to handle XML with an empty value, e.g. <SomeTime />
	if len(data) == 0 {
		return nil
	}

	return d.unmarshal(data, getLayout(data, d.fmt))
}

func (d *DateTime) unmarshal(data []byte, layout string) error {
	if d.fmt == FormatUnix {
		var err error
		d.val, err = parseUnix(data)
		return err
	}

	t, err := time.Parse(layout, strings.ToUpper(string(data)))
	if err != nil {
		return err
	}
	d.val = t
	return nil
}

// String implements the [fmt.Stringer] interface for [DateTime].
// It returns the string value based on the specified [Format] and UTC settings.
func (d DateTime) String() string {
	switch d.fmt {
	case FormatDateOnly:
		return d.val.Format(time.DateOnly)
	case FormatRFC1123:
		return d.val.Format(time.RFC1123)
	case FormatRFC7231:
		return d.val.Format(http.TimeFormat)
	case FormatTimeOnly:
		return d.val.Format(time.TimeOnly)
	case FormatUnix:
		return fmt.Sprintf("%d", d.val.Unix())
	default:
		// default to RFC3339
		return d.val.Format(time.RFC3339Nano)
	}
}

// Time returns the [time.Time] value for this [DateTime].
func (d DateTime) Time() time.Time {
	return d.val
}

// Azure reports time in UTC but it doesn't include the 'Z' time zone suffix in some cases.
var tzOffsetRegex = regexp.MustCompile(`(?:Z|z|\+|-)(?:\d+:\d+)*"*$`)

const (
	utcDateTime    = "2006-01-02T15:04:05.999999999"
	utcDateTimeNoT = "2006-01-02 15:04:05.999999999"
	dateTimeNoT    = `2006-01-02 15:04:05.999999999Z07:00`
)

func getLayout(data []byte, format Format) string {
	if format == FormatDateOnly {
		return time.DateOnly
	} else if format == FormatRFC1123 {
		return time.RFC1123
	} else if format == FormatRFC7231 {
		return http.TimeFormat
	} else if format == FormatTimeOnly {
		return time.TimeOnly
	}

	// for RFC3339 there are several corner-cases we need to handle
	tzOffset := tzOffsetRegex.Match(data)
	hasT := strings.Contains(string(data), "T") || strings.Contains(string(data), "t")
	var layout string
	if tzOffset && hasT {
		layout = time.RFC3339Nano
	} else if tzOffset {
		layout = dateTimeNoT
	} else if hasT {
		layout = utcDateTime
	} else {
		layout = utcDateTimeNoT
	}
	return layout
}

func parseUnix(data []byte) (time.Time, error) {
	sec, err := strconv.ParseInt(string(data), 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(sec, 0), nil
}
