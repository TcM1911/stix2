// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSoftware(t *testing.T) {
	assert := assert.New(t)

	val := "Software name"
	testStr := "Test string"

	t.Run("missing_property", func(t *testing.T) {
		obj, err := NewSoftware("", nil)
		assert.Nil(obj)
		assert.Equal(ErrInvalidParameter, err)
	})

	t.Run("with_property", func(t *testing.T) {
		obj, err := NewSoftware(val, nil)
		assert.NotNil(obj)
		assert.NoError(err)
	})

	t.Run("payload_with_options", func(t *testing.T) {
		marking := make([]*GranularMarking, 0)
		objmark := []Identifier{Identifier("id")}
		specVer := "2.0"

		opts := []SoftwareOption{
			SoftwareOptionGranularMarking(marking),
			SoftwareOptionObjectMarking(objmark),
			SoftwareOptionSpecVersion(specVer),
			SoftwareOptionDefanged(true),
			SoftwareOptionExtension("test", struct{}{}),
			//
			SoftwareOptionCPE(testStr),
			SoftwareOptionLanguages([]string{testStr}),
			SoftwareOptionVendor(testStr),
			SoftwareOptionVersion(testStr),
		}
		obj, err := NewSoftware(val, opts...)
		assert.NotNil(obj)
		assert.NoError(err)
		assert.Equal(marking, obj.GranularMarking)
		assert.Equal(objmark, obj.ObjectMarking)
		assert.Equal(specVer, obj.SpecVersion)
		assert.True(obj.Defanged)

		assert.Equal(val, obj.Name)
		assert.Equal(testStr, obj.CPE)
		assert.Equal([]string{testStr}, obj.Languages)
		assert.Equal(testStr, obj.Vendor)
		assert.Equal(testStr, obj.Version)
	})

	t.Run("id-generation", func(t *testing.T) {
		tests := []struct {
			name    string
			cpe     string
			vendor  string
			version string
			id      string
		}{
			{
				"Word",
				"",
				"",
				"",
				"software--b2ad0d37-3ded-5b98-96f6-8fbb994ba540",
			},
			{
				"Word",
				"cpe:2.3:a:microsoft:word:2000:*:*:*:*:*:*:*",
				"",
				"",
				"software--2a04f5b2-6a03-5762-bb36-5fd126e20d6c",
			},
			{
				"Word",
				"cpe:2.3:a:microsoft:word:2000:*:*:*:*:*:*:*",
				"Microsoft",
				"",
				"software--cfdedf86-ec9c-5769-ae75-2062f68c3313",
			},
			{
				"Word",
				"cpe:2.3:a:microsoft:word:2000:*:*:*:*:*:*:*",
				"Microsoft",
				"2002",
				"software--c9ce663b-b8f8-5256-8cd9-3c0db09808dd",
			},
		}
		for _, test := range tests {
			opts := make([]SoftwareOption, 0, 5)
			if test.cpe != "" {
				opts = append(opts, SoftwareOptionCPE(test.cpe))
			}
			if test.vendor != "" {
				opts = append(opts, SoftwareOptionVendor(test.vendor))
			}
			if test.version != "" {
				opts = append(opts, SoftwareOptionVersion(test.version))
			}
			obj, err := NewSoftware(test.name, opts...)
			assert.NoError(err)
			assert.Equal(Identifier(test.id), obj.ID)
		}
	})

	// t.Run("parse_json", func(t *testing.T) {
	// 	data := []byte(``)
	// 	var obj *Software
	// 	err := json.Unmarshal(data, &obj)
	// 	assert.NoError(err)
	// 	assert.Equal(Identifier("network-traffic--2568d22a-8998-58eb-99ec-3c8ca74f527d"), obj.ID)
	// 	assert.Equal("2.1", obj.SpecVersion)
	// 	assert.Equal(TypeSoftware, obj.Type)
	// 	assert.Equal(Identifier("ipv4-addr--4d22aae0-2bf9-5427-8819-e4f6abf20a53"), obj.Src)
	// 	assert.Equal(Identifier("ipv4-addr--ff26c055-6336-5bc5-b98d-13d6226742dd"), obj.Dst)
	// 	assert.Equal("tcp", obj.Protocols[0])
	// })
}
