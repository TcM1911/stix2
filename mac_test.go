// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMACAddress(t *testing.T) {
	assert := assert.New(t)

	val := "d2:fb:49:24:37:18"

	t.Run("missing_property", func(t *testing.T) {
		obj, err := NewMACAddress("")
		assert.Nil(obj)
		assert.Equal(ErrInvalidParameter, err)
	})

	t.Run("with_property", func(t *testing.T) {
		obj, err := NewMACAddress(val, nil)
		assert.NotNil(obj)
		assert.NoError(err)
	})

	t.Run("payload_with_options", func(t *testing.T) {
		marking := make([]*GranularMarking, 0)
		objmark := []Identifier{Identifier("id")}
		specVer := "2.0"

		opts := []STIXOption{
			OptionGranularMarking(marking),
			OptionObjectMarking(objmark),
			OptionSpecVersion(specVer),
			OptionDefanged(true),
		}
		obj, err := NewMACAddress(val, opts...)
		assert.NotNil(obj)
		assert.NoError(err)
		assert.Equal(marking, obj.GranularMarking)
		assert.Equal(objmark, obj.ObjectMarking)
		assert.Equal(specVer, obj.SpecVersion)
		assert.True(obj.Defanged)

		assert.Equal(val, obj.Value)
	})

	t.Run("id-generation", func(t *testing.T) {
		tests := []struct {
			name string
			id   string
		}{
			{val, "mac-addr--08900593-0265-52fc-93c0-5b4a942f5887"},
		}
		for _, test := range tests {
			obj, err := NewMACAddress(test.name)
			assert.NoError(err)
			assert.Equal(Identifier(test.id), obj.ID)
		}
	})

	t.Run("parse_json", func(t *testing.T) {
		data := []byte(`{
  "type": "mac-addr",
  "spec_version": "2.1",
  "id": "mac-addr--65cfcf98-8a6e-5a1b-8f61-379ac4f92d00",
  "value": "d2:fb:49:24:37:18"
}`)
		var obj *MACAddress
		err := json.Unmarshal(data, &obj)
		assert.NoError(err)
		assert.Equal(Identifier("mac-addr--65cfcf98-8a6e-5a1b-8f61-379ac4f92d00"), obj.ID)
		assert.Equal("2.1", obj.SpecVersion)
		assert.Equal(TypeMACAddress, obj.Type)
		assert.Equal("d2:fb:49:24:37:18", obj.Value)
	})
}
