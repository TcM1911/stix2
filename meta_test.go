// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestLanguageContent(t *testing.T) {
	assert := assert.New(t)

	object := Identifier("ref")
	content := map[string]map[string]interface{}{
		"de": {
			"name":        "Bank Angriff",
			"description": "Weitere Informationen über Banküberfall",
		},
	}

	t.Run("missing_property", func(t *testing.T) {
		obj, err := NewLanguageContent("", nil)
		assert.Nil(obj)
		assert.Equal(ErrPropertyMissing, err)
	})

	t.Run("no_optional", func(t *testing.T) {
		obj, err := NewLanguageContent(object, content, nil)
		assert.NotNil(obj)
		assert.NoError(err)
	})

	t.Run("with_options", func(t *testing.T) {
		conf := 50
		ts := &Timestamp{time.Now()}
		createdBy := NewIdentifier(TypeIdentity)
		ref := &ExternalReference{}
		marking := make([]*GranularMarking, 0)
		labels := []string{"tag1", "tag2"}
		objmark := []Identifier{Identifier("id")}
		specVer := "2.0"

		opts := []STIXOption{
			OptionConfidence(conf),
			OptionCreated(ts),
			OptionModified(ts),
			OptionCreatedBy(createdBy),
			OptionExternalReferences([]*ExternalReference{ref}),
			OptionGranularMarking(marking),
			OptionLabels(labels),
			OptionObjectMarking(objmark),
			OptionRevoked(true),
			OptionSpecVersion(specVer),
			//
			OptionObjectModified(ts),
		}
		obj, err := NewLanguageContent(object, content, opts...)
		assert.NotNil(obj)
		assert.NoError(err)
		assert.Equal(conf, obj.Confidence)
		assert.Equal(ts, obj.Created)
		assert.Equal(ts, obj.Modified)
		assert.Equal(createdBy, obj.CreatedBy)
		assert.Contains(obj.ExternalReferences, ref)
		assert.Equal(marking, obj.GranularMarking)
		assert.Equal(labels, obj.Labels)
		assert.Equal(objmark, obj.ObjectMarking)
		assert.True(obj.Revoked)
		assert.Equal(specVer, obj.SpecVersion)

		assert.Equal(object, obj.Object)
		assert.Equal(content, obj.Contents)
		assert.Equal(ts, obj.ObjectModified)
	})

	t.Run("parse_json", func(t *testing.T) {
		data := []byte(`
{
  "type": "language-content",
  "id": "language-content--b86bd89f-98bb-4fa9-8cb2-9ad421da981d",
  "spec_version": "2.1",
  "created": "2017-02-08T21:31:22.007Z",
  "modified": "2017-02-08T21:31:22.007Z",
  "object_ref": "campaign--12a111f0-b824-4baf-a224-83b80237a094",
  "object_modified": "2017-02-08T21:31:22.007Z",
  "contents":
    {
    "de": {
      "name": "Bank Angriff",
      "description": "Weitere Informationen über Banküberfall"
    },
    "fr": {
      "name": "Attaque Bank",
      "description": "Plus d'informations sur la crise bancaire"
    }
  }
}
		`)
		var obj *LanguageContent
		err := json.Unmarshal(data, &obj)
		assert.NoError(err)
		assert.Equal(Identifier("language-content--b86bd89f-98bb-4fa9-8cb2-9ad421da981d"), obj.ID)
		assert.Equal("2.1", obj.SpecVersion)
		assert.Equal(TypeLanguageContent, obj.Type)
		assert.Equal(Identifier("campaign--12a111f0-b824-4baf-a224-83b80237a094"), obj.Object)
		assert.Len(obj.Contents, 2)
		assert.Equal("Attaque Bank", obj.Contents["fr"]["name"])
		assert.Equal("Plus d'informations sur la crise bancaire", obj.Contents["fr"]["description"])
	})
}

func TestMarkingDefinition(t *testing.T) {
	assert := assert.New(t)

	typ := "statement"
	name := "Name"
	def := StatementMarking{Statement: "A statement"}

	t.Run("missing_property", func(t *testing.T) {
		obj, err := NewMarkingDefinition("", nil)
		assert.Nil(obj)
		assert.Equal(ErrPropertyMissing, err)
	})

	t.Run("no_optional", func(t *testing.T) {
		obj, err := NewMarkingDefinition(typ, def, nil)
		assert.NotNil(obj)
		assert.NoError(err)
	})

	t.Run("with_options", func(t *testing.T) {
		ts := &Timestamp{time.Now()}
		createdBy := NewIdentifier(TypeIdentity)
		ref := &ExternalReference{}
		marking := make([]*GranularMarking, 0)
		objmark := []Identifier{Identifier("id")}
		specVer := "2.0"

		opts := []STIXOption{
			OptionCreated(ts),
			OptionCreatedBy(createdBy),
			OptionExternalReferences([]*ExternalReference{ref}),
			OptionGranularMarking(marking),
			OptionObjectMarking(objmark),
			OptionSpecVersion(specVer),
			//
			OptionName(name),
		}
		obj, err := NewMarkingDefinition(typ, def, opts...)
		assert.NotNil(obj)
		assert.NoError(err)
		assert.Equal(ts, obj.Created)
		assert.Equal(createdBy, obj.CreatedBy)
		assert.Contains(obj.ExternalReferences, ref)
		assert.Equal(marking, obj.GranularMarking)
		assert.Equal(objmark, obj.ObjectMarking)
		assert.Equal(specVer, obj.SpecVersion)

		assert.Equal(name, obj.Name)
		assert.Equal(typ, obj.DefinitionType)
		assert.Equal(def, obj.Definition)
	})

	t.Run("parse_json", func(t *testing.T) {
		data := []byte(
			`
{
  "type": "marking-definition",
  "spec_version": "2.1",
  "id": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
  "created": "2016-08-01T00:00:00.000Z",
  "definition_type": "statement",
  "definition": {
    "statement": "Copyright 2019, Example Corp"
  }
}
`)
		var obj *MarkingDefinition
		err := json.Unmarshal(data, &obj)
		assert.NoError(err)
		assert.Equal(Identifier("marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"), obj.ID)
		assert.Equal("2.1", obj.SpecVersion)
		assert.Equal(TypeMarkingDefinition, obj.Type)
		assert.Equal("statement", obj.DefinitionType)
		assert.Len(obj.Definition, 1)
		def := obj.Definition.(map[string]interface{})
		assert.Equal("Copyright 2019, Example Corp", def["statement"])
	})
}

func TestTLPMarking(t *testing.T) {
	assert := assert.New(t)
	ts, err := time.Parse(time.RFC3339Nano, "2017-01-20T00:00:00.000Z")
	assert.NoError(err)
	stamp := &Timestamp{ts}

	t.Run("white", func(t *testing.T) {
		assert.Equal(Identifier("marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"), TLPWhite.ID)
		assert.Equal("tlp", TLPWhite.DefinitionType)
		assert.Equal("TLP:WHITE", TLPWhite.Name)
		assert.Equal(stamp, TLPWhite.Created)
		def := TLPWhite.Definition.(map[string]interface{})
		assert.Equal("white", def["tlp"])
	})

	t.Run("green", func(t *testing.T) {
		assert.Equal(Identifier("marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"), TLPGreen.ID)
		assert.Equal("tlp", TLPGreen.DefinitionType)
		assert.Equal("TLP:GREEN", TLPGreen.Name)
		assert.Equal(stamp, TLPGreen.Created)
		def := TLPGreen.Definition.(map[string]interface{})
		assert.Equal("green", def["tlp"])
	})

	t.Run("amber", func(t *testing.T) {
		assert.Equal(Identifier("marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"), TLPAmber.ID)
		assert.Equal("tlp", TLPAmber.DefinitionType)
		assert.Equal("TLP:AMBER", TLPAmber.Name)
		assert.Equal(stamp, TLPAmber.Created)
		def := TLPAmber.Definition.(map[string]interface{})
		assert.Equal("amber", def["tlp"])
	})

	t.Run("red", func(t *testing.T) {
		assert.Equal(Identifier("marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"), TLPRed.ID)
		assert.Equal("tlp", TLPRed.DefinitionType)
		assert.Equal("TLP:RED", TLPRed.Name)
		assert.Equal(stamp, TLPRed.Created)
		def := TLPRed.Definition.(map[string]interface{})
		assert.Equal("red", def["tlp"])
	})
}
