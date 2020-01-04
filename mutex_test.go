// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMutex(t *testing.T) {
	assert := assert.New(t)

	val := "__CLEANSWEEP__"

	t.Run("missing_property", func(t *testing.T) {
		obj, err := NewMutex("")
		assert.Nil(obj)
		assert.Equal(ErrInvalidParameter, err)
	})

	t.Run("with_property", func(t *testing.T) {
		obj, err := NewMutex(val, nil)
		assert.NotNil(obj)
		assert.NoError(err)
	})

	t.Run("payload_with_options", func(t *testing.T) {
		marking := &GranularMarking{}
		objmark := []Identifier{Identifier("id")}
		specVer := "2.0"

		opts := []MutexOption{
			MutexOptionGranularMarking(marking),
			MutexOptionObjectMarking(objmark),
			MutexOptionSpecVersion(specVer),
			MutexOptionDefanged(true),
			MutexOptionExtension("test", struct{}{}),
		}
		obj, err := NewMutex(val, opts...)
		assert.NotNil(obj)
		assert.NoError(err)
		assert.Equal(marking, obj.GranularMarking)
		assert.Equal(objmark, obj.ObjectMarking)
		assert.Equal(specVer, obj.SpecVersion)
		assert.True(obj.Defanged)

		assert.Equal(val, obj.Name)
	})

	t.Run("id-generation", func(t *testing.T) {
		tests := []struct {
			name string
			id   string
		}{
			{val, "mutex--840b4dcd-0db1-5190-89c1-1b664c5ab0ea"},
		}
		for _, test := range tests {
			obj, err := NewMutex(test.name)
			assert.NoError(err)
			assert.Equal(Identifier(test.id), obj.ID)
		}
	})

	t.Run("parse_json", func(t *testing.T) {
		data := []byte(`{
  "type": "mutex",
  "spec_version": "2.1",
  "id": "mutex--eba44954-d4e4-5d3b-814c-2b17dd8de300",
  "name": "__CLEANSWEEP__"
}`)
		var obj *Mutex
		err := json.Unmarshal(data, &obj)
		assert.NoError(err)
		assert.Equal(Identifier("mutex--eba44954-d4e4-5d3b-814c-2b17dd8de300"), obj.ID)
		assert.Equal("2.1", obj.SpecVersion)
		assert.Equal(TypeMutex, obj.Type)
		assert.Equal("__CLEANSWEEP__", obj.Name)
	})
}
