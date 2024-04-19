//go:build go1.18
// +build go1.18

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package datetime

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStringFormatsUTC(t *testing.T) {
	time1 := time.Date(2024, 7, 17, 13, 15, 0, 0, time.UTC)

	dt := New(FormatDateOnly, &Options{
		From: time1,
	})
	assert.EqualValues(t, "2024-07-17", dt.String())

	dt = New(FormatRFC1123, &Options{
		From: time1,
	})
	assert.EqualValues(t, "Wed, 17 Jul 2024 13:15:00 UTC", dt.String())

	dt = New(FormatRFC3339, &Options{
		From: time1,
	})
	assert.EqualValues(t, "2024-07-17T13:15:00Z", dt.String())

	dt = New(FormatRFC7231, &Options{
		From: time1,
	})
	assert.EqualValues(t, "Wed, 17 Jul 2024 13:15:00 GMT", dt.String())

	dt = New(FormatTimeOnly, &Options{
		From: time1,
	})
	assert.EqualValues(t, "13:15:00", dt.String())

	dt = New(FormatUnix, &Options{
		From: time1,
	})
	assert.EqualValues(t, "1721222100", dt.String())
}

func TestStringFormatsWithOffset(t *testing.T) {
	loc, err := time.LoadLocation("America/Los_Angeles")
	require.NoError(t, err)
	time1 := time.Date(2024, 7, 17, 13, 15, 0, 0, loc)

	dt := New(FormatDateOnly, &Options{
		From: time1,
	})
	assert.EqualValues(t, "2024-07-17", dt.String())

	dt = New(FormatRFC1123, &Options{
		From: time1,
	})
	assert.EqualValues(t, "Wed, 17 Jul 2024 13:15:00 PDT", dt.String())

	dt = New(FormatRFC3339, &Options{
		From: time1,
	})
	assert.EqualValues(t, "2024-07-17T13:15:00-07:00", dt.String())

	dt = New(FormatRFC7231, &Options{
		From: time1,
	})
	assert.EqualValues(t, "Wed, 17 Jul 2024 13:15:00 GMT", dt.String())

	dt = New(FormatTimeOnly, &Options{
		From: time1,
	})
	assert.EqualValues(t, "13:15:00", dt.String())

	dt = New(FormatUnix, &Options{
		From: time1,
	})
	assert.EqualValues(t, "1721247300", dt.String())
}

func TestMarshalMethods(t *testing.T) {
	time1 := time.Date(2024, 7, 17, 13, 15, 0, 0, time.UTC)
	dt := New(FormatRFC3339, &Options{
		From: time1,
	})

	data, err := dt.MarshalJSON()
	require.NoError(t, err)
	assert.EqualValues(t, `"2024-07-17T13:15:00Z"`, string(data))

	data, err = dt.MarshalText()
	require.NoError(t, err)
	assert.EqualValues(t, "2024-07-17T13:15:00Z", string(data))
}

func TestUnmarshalJSON(t *testing.T) {
	dt := New(FormatDateOnly, nil)
	require.NoError(t, dt.UnmarshalJSON([]byte(`"2024-07-17"`)))
	assert.EqualValues(t, "2024-07-17", dt.String())

	dt = New(FormatRFC1123, nil)
	require.NoError(t, dt.UnmarshalJSON([]byte(`"Wed, 17 Jul 2024 13:15:00 PDT"`)))
	assert.EqualValues(t, "Wed, 17 Jul 2024 13:15:00 PDT", dt.String())

	dt = New(FormatRFC3339, nil)
	require.NoError(t, dt.UnmarshalJSON([]byte(`"2024-07-17T13:15:00Z"`)))
	assert.EqualValues(t, "2024-07-17T13:15:00Z", dt.String())

	dt = New(FormatRFC7231, nil)
	require.NoError(t, dt.UnmarshalJSON([]byte(`"Wed, 17 Jul 2024 13:15:00 GMT"`)))
	assert.EqualValues(t, "Wed, 17 Jul 2024 13:15:00 GMT", dt.String())

	dt = New(FormatTimeOnly, nil)
	require.NoError(t, dt.UnmarshalJSON([]byte(`"13:15:00"`)))
	assert.EqualValues(t, "13:15:00", dt.String())

	dt = New(FormatUnix, nil)
	require.NoError(t, dt.UnmarshalJSON([]byte(`1721222100`)))
	assert.EqualValues(t, "1721222100", dt.String())

	// RFC3339 corner cases

	dt = New(FormatRFC3339, nil)
	require.NoError(t, dt.UnmarshalJSON([]byte(`"2024-07-17t13:15:00Z"`)))
	assert.EqualValues(t, "2024-07-17T13:15:00Z", dt.String())

	dt = New(FormatRFC3339, nil)
	require.NoError(t, dt.UnmarshalJSON([]byte(`"2024-07-17 13:15:00Z"`)))
	assert.EqualValues(t, "2024-07-17T13:15:00Z", dt.String())

	dt = New(FormatRFC3339, nil)
	require.NoError(t, dt.UnmarshalJSON([]byte(`"2024-07-17T13:15:00"`)))
	assert.EqualValues(t, "2024-07-17T13:15:00Z", dt.String())

	dt = New(FormatRFC3339, nil)
	require.NoError(t, dt.UnmarshalJSON([]byte(`"2024-07-17t13:15:00"`)))
	assert.EqualValues(t, "2024-07-17T13:15:00Z", dt.String())

	dt = New(FormatRFC3339, nil)
	require.NoError(t, dt.UnmarshalJSON([]byte(`"2024-07-17 13:15:00"`)))
	assert.EqualValues(t, "2024-07-17T13:15:00Z", dt.String())

	// null time

	dt = New(FormatRFC3339, nil)
	require.NoError(t, dt.UnmarshalJSON(nil))
	assert.True(t, dt.Time().IsZero())

	dt = New(FormatRFC3339, nil)
	require.NoError(t, dt.UnmarshalJSON([]byte("null")))
	assert.True(t, dt.Time().IsZero())
}

func TestUnmarshalText(t *testing.T) {
	dt := New(FormatDateOnly, nil)
	require.NoError(t, dt.UnmarshalText([]byte("2024-07-17")))
	assert.EqualValues(t, "2024-07-17", dt.String())

	dt = New(FormatRFC1123, nil)
	require.NoError(t, dt.UnmarshalText([]byte("Wed, 17 Jul 2024 13:15:00 PDT")))
	assert.EqualValues(t, "Wed, 17 Jul 2024 13:15:00 PDT", dt.String())

	dt = New(FormatRFC3339, nil)
	require.NoError(t, dt.UnmarshalText([]byte("2024-07-17T13:15:00Z")))
	assert.EqualValues(t, "2024-07-17T13:15:00Z", dt.String())

	dt = New(FormatRFC7231, nil)
	require.NoError(t, dt.UnmarshalText([]byte("Wed, 17 Jul 2024 13:15:00 GMT")))
	assert.EqualValues(t, "Wed, 17 Jul 2024 13:15:00 GMT", dt.String())

	dt = New(FormatTimeOnly, nil)
	require.NoError(t, dt.UnmarshalText([]byte("13:15:00")))
	assert.EqualValues(t, "13:15:00", dt.String())

	dt = New(FormatUnix, nil)
	require.NoError(t, dt.UnmarshalText([]byte("1721222100")))
	assert.EqualValues(t, "1721222100", dt.String())

	// empty time

	dt = New(FormatRFC3339, nil)
	require.NoError(t, dt.UnmarshalText([]byte("")))
	assert.True(t, dt.Time().IsZero())

	dt = New(FormatRFC3339, nil)
	require.NoError(t, dt.UnmarshalText(nil))
	assert.True(t, dt.Time().IsZero())
}

func TestUnmarshalErrors(t *testing.T) {
	dt := New(FormatUnix, nil)
	require.Error(t, dt.UnmarshalJSON([]byte("not-unix-timestamp")))
	assert.True(t, dt.Time().IsZero())

	dt = New(FormatRFC3339, nil)
	require.Error(t, dt.UnmarshalText([]byte("not-rfc3339-time")))
	assert.True(t, dt.Time().IsZero())
}

func TestSliceWithNil(t *testing.T) {
	time1 := time.Date(2024, 4, 17, 13, 15, 0, 0, time.UTC)
	time2 := time.Date(2024, 4, 18, 10, 40, 31, 0, time.UTC)
	src := []*DateTime{
		to.Ptr(New(FormatRFC3339, &Options{
			From: time1,
		})),
		nil,
		to.Ptr(New(FormatRFC3339, &Options{
			From: time2,
		})),
	}
	data, err := json.Marshal(src)
	require.NoError(t, err)
	assert.EqualValues(t, `["2024-04-17T13:15:00Z",null,"2024-04-18T10:40:31Z"]`, data)
}

/*func TestStuff(t *testing.T) {
	// GMT is handled by both RFC1123 and TimeFormat
	// MST blows up TimeFormat
	const val = "Fri, 26 Aug 2022 14:38:00 GMT"
	tt, err := time.Parse(time.RFC1123, val)
	require.NoError(t, err)
	fmt.Println(tt.UTC().String())

	tt, err = time.Parse(http.TimeFormat, val)
	require.NoError(t, err)
	fmt.Println(tt.UTC().String())
}

func TestRFC3339(t *testing.T) {
	const val1 = "2024-04-18T10:40:31Z"
	tt, err := time.Parse(time.RFC3339Nano, val1)
	require.NoError(t, err)
	fmt.Println(tt.String())

	const val2 = "2024-04-18T10:40:31-07:00"
	tt, err = time.Parse(time.RFC3339Nano, val2)
	require.NoError(t, err)
	fmt.Println(tt.String())
	fmt.Println(tt.UTC().String())
}*/
