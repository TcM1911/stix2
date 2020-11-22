// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIPv4Address(t *testing.T) {
	assert := assert.New(t)

	val := "10.0.0.2"

	t.Run("missing_property", func(t *testing.T) {
		obj, err := NewIPv4Address("")
		assert.Nil(obj)
		assert.Equal(ErrInvalidParameter, err)
	})

	t.Run("with_property", func(t *testing.T) {
		obj, err := NewIPv4Address(val, nil)
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
		obj, err := NewIPv4Address(val, opts...)
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
			{val, "ipv4-addr--48a7c3d8-855f-547b-ad6e-a717a7ca79f1"},
		}
		for _, test := range tests {
			obj, err := NewIPv4Address(test.name)
			assert.NoError(err)
			assert.Equal(Identifier(test.id), obj.ID)
		}
	})

	t.Run("parse_json", func(t *testing.T) {
		data := []byte(`{
  "type": "ipv4-addr",
  "spec_version": "2.1",
  "id": "ipv4-addr--ff26c055-6336-5bc5-b98d-13d6226742dd",
  "value": "198.51.100.3"
}`)
		var obj *IPv4Address
		err := json.Unmarshal(data, &obj)
		assert.NoError(err)
		assert.Equal(Identifier("ipv4-addr--ff26c055-6336-5bc5-b98d-13d6226742dd"), obj.ID)
		assert.Equal("2.1", obj.SpecVersion)
		assert.Equal(TypeIPv4Addr, obj.Type)
		assert.Equal("198.51.100.3", obj.Value)
	})
}

func TestIPv4AddressResolvesTo(t *testing.T) {
	assert := assert.New(t)
	val := "10.0.0.2"

	t.Run("mac", func(t *testing.T) {
		obj, err := NewIPv4Address(val)
		assert.NoError(err)
		id := NewIdentifier(TypeMACAddress)
		rel, err := obj.AddResolvesTo(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(obj.ID, rel.Source)
		assert.Equal(RelationshipTypeResolvesTo, rel.RelationshipType)
	})

	t.Run("invalid_type", func(t *testing.T) {
		obj, err := NewIPv4Address(val)
		assert.NoError(err)
		id := NewIdentifier(TypeMalware)
		rel, err := obj.AddResolvesTo(id)
		assert.Equal(err, ErrInvalidParameter)
		assert.Nil(rel)
	})
}

func TestIPv4AddressBelongsTo(t *testing.T) {
	assert := assert.New(t)
	val := "10.0.0.2"

	t.Run("as", func(t *testing.T) {
		obj, err := NewIPv4Address(val)
		assert.NoError(err)
		id := NewIdentifier(TypeAutonomousSystem)
		rel, err := obj.AddBelongsTo(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(obj.ID, rel.Source)
		assert.Equal(RelationshipTypeBelongsTo, rel.RelationshipType)
	})

	t.Run("invalid_type", func(t *testing.T) {
		obj, err := NewIPv4Address(val)
		assert.NoError(err)
		id := NewIdentifier(TypeMalware)
		rel, err := obj.AddBelongsTo(id)
		assert.Equal(err, ErrInvalidParameter)
		assert.Nil(rel)
	})
}

func TestIPv6Address(t *testing.T) {
	assert := assert.New(t)

	val := "2001:0db8:85a3:0000:0000:8a2e:0370:7334"

	t.Run("missing_property", func(t *testing.T) {
		obj, err := NewIPv6Address("")
		assert.Nil(obj)
		assert.Equal(ErrInvalidParameter, err)
	})

	t.Run("with_property", func(t *testing.T) {
		obj, err := NewIPv6Address(val, nil)
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
		obj, err := NewIPv6Address(val, opts...)
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
			{val, "ipv6-addr--569e5b47-8700-54ed-a097-36262ace5b64"},
		}
		for _, test := range tests {
			obj, err := NewIPv6Address(test.name)
			assert.NoError(err)
			assert.Equal(Identifier(test.id), obj.ID)
		}
	})

	t.Run("parse_json", func(t *testing.T) {
		data := []byte(`{ 
  "type": "ipv6-addr",
  "spec_version": "2.1",
  "id": "ipv6-addr--1e61d36c-a16c-53b7-a80f-2a00161c96b1",
  "value": "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
}`)
		var obj *IPv6Address
		err := json.Unmarshal(data, &obj)
		assert.NoError(err)
		assert.Equal(Identifier("ipv6-addr--1e61d36c-a16c-53b7-a80f-2a00161c96b1"), obj.ID)
		assert.Equal("2.1", obj.SpecVersion)
		assert.Equal(TypeIPv6Addr, obj.Type)
		assert.Equal("2001:0db8:85a3:0000:0000:8a2e:0370:7334", obj.Value)
	})
}

func TestIPv6AddressResolvesTo(t *testing.T) {
	assert := assert.New(t)
	val := "2001:0db8:85a3:0000:0000:8a2e:0370:7334"

	t.Run("mac", func(t *testing.T) {
		obj, err := NewIPv6Address(val)
		assert.NoError(err)
		id := NewIdentifier(TypeMACAddress)
		rel, err := obj.AddResolvesTo(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(obj.ID, rel.Source)
		assert.Equal(RelationshipTypeResolvesTo, rel.RelationshipType)
	})

	t.Run("invalid_type", func(t *testing.T) {
		obj, err := NewIPv6Address(val)
		assert.NoError(err)
		id := NewIdentifier(TypeMalware)
		rel, err := obj.AddResolvesTo(id)
		assert.Equal(err, ErrInvalidParameter)
		assert.Nil(rel)
	})
}

func TestIPv6AddressBelongsTo(t *testing.T) {
	assert := assert.New(t)
	val := "2001:0db8:85a3:0000:0000:8a2e:0370:7334"

	t.Run("as", func(t *testing.T) {
		obj, err := NewIPv6Address(val)
		assert.NoError(err)
		id := NewIdentifier(TypeAutonomousSystem)
		rel, err := obj.AddBelongsTo(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(obj.ID, rel.Source)
		assert.Equal(RelationshipTypeBelongsTo, rel.RelationshipType)
	})

	t.Run("invalid_type", func(t *testing.T) {
		obj, err := NewIPv6Address(val)
		assert.NoError(err)
		id := NewIdentifier(TypeMalware)
		rel, err := obj.AddBelongsTo(id)
		assert.Equal(err, ErrInvalidParameter)
		assert.Nil(rel)
	})
}
