// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRegistryKey(t *testing.T) {
	assert := assert.New(t)

	testStr := "test string"
	val := []*RegistryValue{{Name: "name", Data: "data", DataType: RegSz}}
	ts := &Timestamp{time.Now()}
	ref := Identifier("ref")
	num := int64(42)

	t.Run("missing_property", func(t *testing.T) {
		obj, err := NewRegistryKey()
		assert.Nil(obj)
		assert.Equal(ErrPropertyMissing, err)
	})

	t.Run("with_property", func(t *testing.T) {
		obj, err := NewRegistryKey(nil)
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
			OptionExtension("test", struct{}{}),
			//
			OptionKey(testStr),
			OptionValues(val),
			OptionModifiedTime(ts),
			OptionCreatorUser(ref),
			OptionNumberOfSubkeys(num),
		}
		obj, err := NewRegistryKey(opts...)
		assert.NotNil(obj)
		assert.NoError(err)
		assert.Equal(marking, obj.GranularMarking)
		assert.Equal(objmark, obj.ObjectMarking)
		assert.Equal(specVer, obj.SpecVersion)
		assert.True(obj.Defanged)

		assert.Equal(testStr, obj.Key)
		assert.Equal(val, obj.Values)
		assert.Equal(ts, obj.ModifiedTime)
		assert.Equal(ref, obj.CreatorUser)
		assert.Equal(num, obj.NumberOfSubkeys)
	})

	t.Run("id-generation", func(t *testing.T) {
		tests := []struct {
			key    string
			values []*RegistryValue
			id     string
		}{
			{
				testStr,
				nil,
				"windows-registry-key--95c4c7a8-d804-505a-be56-e48cf0907412",
			},
			{
				testStr,
				val,
				"windows-registry-key--a292f379-2da1-5606-a5ae-36124b43ef1b",
			},
		}
		for _, test := range tests {
			opts := make([]STIXOption, 0, 3)
			if test.key != "" {
				opts = append(opts, OptionKey(test.key))
			}
			if test.values != nil {
				opts = append(opts, OptionValues(test.values))
			}
			obj, err := NewRegistryKey(opts...)
			assert.NoError(err)
			assert.Equal(Identifier(test.id), obj.ID)
		}
	})

	t.Run("parse_json", func(t *testing.T) {
		data := []byte(`
{
  "type": "windows-registry-key",
  "spec_version": "2.1",
  "id": "windows-registry-key--2ba37ae7-2745-5082-9dfd-9486dad41016",
  "key": "hkey_local_machine\\system\\bar\\foo",
  "values": [
    {
      "name": "Foo",
      "data": "qwerty",
      "data_type": "REG_SZ"
    },
    {
      "name": "Bar",
      "data": "42",
      "data_type": "REG_DWORD"
    }
  ]
}
	`)
		var obj *RegistryKey
		err := json.Unmarshal(data, &obj)
		assert.NoError(err)
		assert.Equal(Identifier("windows-registry-key--2ba37ae7-2745-5082-9dfd-9486dad41016"), obj.ID)
		assert.Equal("2.1", obj.SpecVersion)
		assert.Equal(TypeRegistryKey, obj.Type)
		assert.Equal("hkey_local_machine\\system\\bar\\foo", obj.Key)
		assert.Len(obj.Values, 2)
		assert.Equal("Foo", obj.Values[0].Name)
		assert.Equal("qwerty", obj.Values[0].Data)
		assert.Equal(RegSz, obj.Values[0].DataType)
		assert.Equal("Bar", obj.Values[1].Name)
		assert.Equal("42", obj.Values[1].Data)
		assert.Equal(RegDword, obj.Values[1].DataType)
	})
}

func TestRegistryDataType(t *testing.T) {
	assert := assert.New(t)
	t.Run("valid", func(t *testing.T) {
		data, err := RegBinary.MarshalJSON()
		assert.NoError(err)
		assert.Equal(`"REG_BINARY"`, string(data))

		var actual RegistryDataType
		ptr := &actual
		err = ptr.UnmarshalJSON([]byte(`"REG_BINARY"`))
		assert.NoError(err)
		assert.Equal(RegBinary, actual)
	})
	t.Run("invalid", func(t *testing.T) {
		var actual RegistryDataType
		ptr := &actual
		err := ptr.UnmarshalJSON([]byte(`"AAAAAA"`))
		assert.NoError(err)
		assert.Equal(RegUnknownValue, actual)
	})
	t.Run("invalid-short", func(t *testing.T) {
		var actual RegistryDataType
		ptr := &actual
		err := ptr.UnmarshalJSON([]byte(`A`))
		assert.NoError(err)
		assert.Equal(RegUnknownValue, actual)
	})
}
