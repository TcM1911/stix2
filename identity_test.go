// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestIdentity(t *testing.T) {
	assert := assert.New(t)

	name := "New campaign"
	class := IdentityClassUnspecified

	t.Run("missing_property", func(t *testing.T) {
		obj, err := NewIdentity("", "")
		assert.Nil(obj)
		assert.Equal(ErrPropertyMissing, err)
	})

	t.Run("no_optional", func(t *testing.T) {
		obj, err := NewIdentity(name, class, nil)
		assert.NotNil(obj)
		assert.NoError(err)
	})

	t.Run("with_options", func(t *testing.T) {
		conf := 50
		desc := "My description"
		ts := &Timestamp{time.Now()}
		createdBy := NewIdentifier(TypeIdentity)
		ref := &ExternalReference{}
		marking := make([]*GranularMarking, 0)
		labels := []string{"tag1", "tag2"}
		lang := "en"
		objmark := []Identifier{Identifier("id")}
		specVer := "2.0"

		roles := []string{"CEO", "Retailer"}
		sectors := []string{IdentitySectorDefence, IdentitySectorEntertainment}
		contact := "123 Main ST"

		opts := []IdentityOption{
			IdentityOptionConfidence(conf),
			IdentityOptionCreated(ts),
			IdentityOptionModified(ts),
			IdentityOptionCreatedBy(createdBy),
			IdentityOptionExternalReferences([]*ExternalReference{ref}),
			IdentityOptionGranularMarking(marking),
			IdentityOptionLabels(labels),
			IdentityOptionLang(lang),
			IdentityOptionObjectMarking(objmark),
			IdentityOptionRevoked(true),
			IdentityOptionSpecVersion(specVer),
			//
			IdentityOptionDescription(desc),
			IdentityOptionRoles(roles),
			IdentityOptionSectors(sectors),
			IdentityOptionContactInformation(contact),
		}
		obj, err := NewIdentity(name, class, opts...)
		assert.NotNil(obj)
		assert.NoError(err)
		assert.Equal(conf, obj.Confidence)
		assert.Equal(ts, obj.Created)
		assert.Equal(ts, obj.Modified)
		assert.Equal(createdBy, obj.CreatedBy)
		assert.Contains(obj.ExternalReferences, ref)
		assert.Equal(marking, obj.GranularMarking)
		assert.Equal(labels, obj.Labels)
		assert.Equal(lang, obj.Lang)
		assert.Equal(objmark, obj.ObjectMarking)
		assert.True(obj.Revoked)
		assert.Equal(specVer, obj.SpecVersion)

		assert.Equal(desc, obj.Description)
		assert.Equal(roles, obj.Roles)
		assert.Equal(sectors, obj.Sectors)
		assert.Equal(contact, obj.ContactInformation)
	})

	t.Run("parse_json", func(t *testing.T) {
		data := []byte(`{
  "type": "identity",
  "spec_version": "2.1",
  "id": "identity--023d105b-752e-4e3c-941c-7d3f3cb15e9e",
  "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
  "created": "2016-04-06T20:03:00.000Z",
  "modified": "2016-04-06T20:03:00.000Z",
  "name": "John Smith",
  "identity_class": "individual"
}`)
		ts, err := time.Parse(time.RFC3339Nano, "2016-04-06T20:03:00.000Z")
		assert.NoError(err)
		var obj *Identity
		err = json.Unmarshal(data, &obj)
		assert.NoError(err)
		assert.Equal(Identifier("identity--023d105b-752e-4e3c-941c-7d3f3cb15e9e"), obj.ID)
		assert.Equal("2.1", obj.SpecVersion)
		assert.Equal(TypeIdentity, obj.Type)
		assert.Equal("John Smith", obj.Name)
		assert.Equal(ts, obj.Created.Time)
		assert.Equal(ts, obj.Modified.Time)
		assert.Equal(IdentityClassIndividual, obj.IdentityClass)
	})
}

func TestIdentityMitigates(t *testing.T) {
	assert := assert.New(t)

	t.Run("vulnerability", func(t *testing.T) {
		obj, err := NewIdentity("name", "class")
		assert.NoError(err)
		id := NewIdentifier(TypeLocation)
		rel, err := obj.AddLocatedAt(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(obj.ID, rel.Source)
	})

	t.Run("invalid_type", func(t *testing.T) {
		obj, err := NewIdentity("name", "class")
		assert.NoError(err)
		id := NewIdentifier(TypeIPv4Addr)
		rel, err := obj.AddLocatedAt(id)
		assert.Equal(err, ErrInvalidParameter)
		assert.Nil(rel)
	})
}
