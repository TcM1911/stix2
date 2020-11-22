// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestURL(t *testing.T) {
	assert := assert.New(t)

	val := "https://example.com/research/index.html"

	t.Run("missing_property", func(t *testing.T) {
		obj, err := NewURL("")
		assert.Nil(obj)
		assert.Equal(ErrInvalidParameter, err)
	})

	t.Run("with_property", func(t *testing.T) {
		obj, err := NewURL(val, nil)
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
		}
		obj, err := NewURL(val, opts...)
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
			{val, "url--19cabd28-b056-5306-bf6c-9997c8ff59a7"},
		}
		for _, test := range tests {
			obj, err := NewURL(test.name)
			assert.NoError(err)
			assert.Equal(Identifier(test.id), obj.ID)
		}
	})

	t.Run("parse_json", func(t *testing.T) {
		data := []byte(`{  
  "type": "url",
  "spec_version": "2.1",
  "id": "url--c1477287-23ac-5971-a010-5c287877fa60",
  "value": "https://example.com/research/index.html"
}`)
		var obj *URL
		err := json.Unmarshal(data, &obj)
		assert.NoError(err)
		assert.Equal(Identifier("url--c1477287-23ac-5971-a010-5c287877fa60"), obj.ID)
		assert.Equal("2.1", obj.SpecVersion)
		assert.Equal(TypeURL, obj.Type)
		assert.Equal(val, obj.Value)
	})
}
