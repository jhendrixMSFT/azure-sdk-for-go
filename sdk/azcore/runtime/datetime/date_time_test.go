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
	"github.com/stretchr/testify/require"
)

func TestSliceWithNil(t *testing.T) {
	time1 := time.Date(2024, 4, 17, 13, 15, 0, 0, time.UTC)
	time2 := time.Date(2024, 4, 18, 10, 40, 31, 0, time.UTC)
	src := []*DateTime{
		to.Ptr(New(FormatRFC3339, true, &Options{
			From: time1,
		})),
		nil,
		to.Ptr(New(FormatRFC3339, true, &Options{
			From: time2,
		})),
	}
	data, err := json.Marshal(src)
	require.NoError(t, err)
	require.EqualValues(t, `["2024-04-17T13:15:00Z",null,"2024-04-18T10:40:31Z"]`, data)
}
