// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDomain(t *testing.T) {
	assert := assert.New(t)

	name := "example.com"
	resolve := Identifier("test")

	t.Run("missing_property", func(t *testing.T) {
		obj, err := NewDomainName("")
		assert.Nil(obj)
		assert.Equal(ErrInvalidParameter, err)
	})

	t.Run("with_property", func(t *testing.T) {
		obj, err := NewDomainName(name, nil)
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
			OptionResolvesTo([]Identifier{resolve}),
		}
		obj, err := NewDomainName(name, opts...)
		assert.NotNil(obj)
		assert.NoError(err)
		assert.Equal(marking, obj.GranularMarking)
		assert.Equal(objmark, obj.ObjectMarking)
		assert.Equal(specVer, obj.SpecVersion)
		assert.True(obj.Defanged)

		assert.Equal(name, obj.Value)
		assert.Contains(obj.ResolvesTo, resolve)
	})

	t.Run("id-generation", func(t *testing.T) {
		tests := []struct {
			name string
			id   string
		}{
			{"example.com", "domain-name--220a2699-5ebf-5b57-bf02-424964bb19c0"},
		}
		for _, test := range tests {
			obj, err := NewDomainName(test.name)
			assert.NoError(err)
			assert.Equal(Identifier(test.id), obj.ID)
		}
	})

	t.Run("parse_json", func(t *testing.T) {
		data := []byte(`{
  "type": "domain-name",
  "spec_version": "2.1",
  "id": "domain-name--3c10e93f-798e-5a26-a0c1-08156efab7f5",
  "value": "example.com"
}`)
		var obj *DomainName
		err := json.Unmarshal(data, &obj)
		assert.NoError(err)
		assert.Equal(Identifier("domain-name--3c10e93f-798e-5a26-a0c1-08156efab7f5"), obj.ID)
		assert.Equal("2.1", obj.SpecVersion)
		assert.Equal(TypeDomainName, obj.Type)
		assert.Equal("example.com", obj.Value)
	})
}

func TestDomainResolvesTo(t *testing.T) {
	assert := assert.New(t)
	val := "example.com"

	t.Run("domain", func(t *testing.T) {
		obj, err := NewDomainName(val)
		assert.NoError(err)
		id := NewIdentifier(TypeDomainName)
		rel, err := obj.AddResolvesTo(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(obj.ID, rel.Source)
	})

	t.Run("ip-v4", func(t *testing.T) {
		obj, err := NewDomainName(val)
		assert.NoError(err)
		id := NewIdentifier(TypeIPv4Addr)
		rel, err := obj.AddResolvesTo(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(obj.ID, rel.Source)
	})

	t.Run("ip-v6", func(t *testing.T) {
		obj, err := NewDomainName(val)
		assert.NoError(err)
		id := NewIdentifier(TypeIPv6Addr)
		rel, err := obj.AddResolvesTo(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(obj.ID, rel.Source)
	})

	t.Run("invalid_type", func(t *testing.T) {
		obj, err := NewDomainName(val)
		assert.NoError(err)
		id := NewIdentifier(TypeMalware)
		rel, err := obj.AddResolvesTo(id)
		assert.Equal(err, ErrInvalidParameter)
		assert.Nil(rel)
	})
}
