// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAS(t *testing.T) {
	assert := assert.New(t)

	num := int64(42)
	name := "System 12"
	rir := "RIPE"

	t.Run("missing_property", func(t *testing.T) {
		obj, err := NewAutonomousSystem(0)
		assert.Nil(obj)
		assert.Equal(ErrInvalidParameter, err)
	})

	t.Run("with_property", func(t *testing.T) {
		obj, err := NewAutonomousSystem(num, nil)
		assert.NotNil(obj)
		assert.NoError(err)
	})

	t.Run("payload_with_options", func(t *testing.T) {
		marking := make([]*GranularMarking, 0)
		objmark := []Identifier{Identifier("id")}
		specVer := "2.0"

		opts := []AutonomousSystemOption{
			ASOptionGranularMarking(marking),
			ASOptionObjectMarking(objmark),
			ASOptionSpecVersion(specVer),
			ASOptionDefanged(true),
			ASOptionExtension("test", struct{}{}),
			//
			ASOptionName(name),
			ASOptionRIR(rir),
		}
		obj, err := NewAutonomousSystem(num, opts...)
		assert.NotNil(obj)
		assert.NoError(err)
		assert.Equal(marking, obj.GranularMarking)
		assert.Equal(objmark, obj.ObjectMarking)
		assert.Equal(specVer, obj.SpecVersion)
		assert.True(obj.Defanged)

		assert.Equal(num, obj.Number)
		assert.Equal(name, obj.Name)
		assert.Equal(rir, obj.RIR)
	})

	t.Run("id-generation", func(t *testing.T) {
		tests := []struct {
			number int64
			id     string
		}{
			{int64(100), "autonomous-system--0a68995b-d4b2-5f3e-810d-1aeeeb0d4b88"},
		}
		for _, test := range tests {
			obj, err := NewAutonomousSystem(test.number)
			assert.NoError(err)
			assert.Equal(Identifier(test.id), obj.ID)
		}
	})

	t.Run("parse_json", func(t *testing.T) {
		data := []byte(`{
  "type": "autonomous-system",
  "spec_version": "2.1",
  "id": "autonomous-system--f720c34b-98ae-597f-ade5-27dc241e8c74",
  "number": 15139,
  "name": "Slime Industries",
  "rir": "ARIN"
}`)
		var obj *AutonomousSystem
		err := json.Unmarshal(data, &obj)
		assert.NoError(err)
		assert.Equal(Identifier("autonomous-system--f720c34b-98ae-597f-ade5-27dc241e8c74"), obj.ID)
		assert.Equal("2.1", obj.SpecVersion)
		assert.Equal(TypeAutonomousSystem, obj.Type)
		assert.Equal(int64(15139), obj.Number)
		assert.Equal("Slime Industries", obj.Name)
		assert.Equal("ARIN", obj.RIR)
	})
}
