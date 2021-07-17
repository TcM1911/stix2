package stix2

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtensionJSONParsing(t *testing.T) {
	assert := assert.New(t)

	t.Run("invalid-extension-format", func(t *testing.T) {
		data := []byte(`{
			"type": "network-traffic",
			"spec_version": "2.1",
			"id": "network-traffic--09ca55c3-97e5-5966-bad0-1d41d557ae13",
			"src_ref": "ipv4-addr--89830c10-2e94-57fa-8ca6-e0537d2719d1",
			"dst_ref": "ipv4-addr--45f4c6fb-2d7d-576a-a571-edc78d899a72",
			"src_port": 3372,
			"dst_port": 80,
			"protocols": ["tcp"],
			"extensions": {
				"invalid": "string"
		  }
		}
`)

		var obj *NetworkTraffic
		err := json.Unmarshal(data, &obj)
		assert.Error(err, fmt.Sprintf("Value: %+v", obj))
	})

	t.Run("invalid-extension-format", func(t *testing.T) {
		data := []byte(`{
		"type": "network-traffic",
		"spec_version": "2.1",
		"id": "network-traffic--09ca55c3-97e5-5966-bad0-1d41d557ae13",
		"src_ref": "ipv4-addr--89830c10-2e94-57fa-8ca6-e0537d2719d1",
		"dst_ref": "ipv4-addr--45f4c6fb-2d7d-576a-a571-edc78d899a72",
		"src_port": 3372,
		"dst_port": 80,
		"protocols": ["tcp"],
		"extensions": "string"
	}
`)

		var obj *NetworkTraffic
		err := json.Unmarshal(data, &obj)
		assert.Error(err)
	})
}

func TestExtensionProperties(t *testing.T) {
	assert := assert.New(t)

	t.Run("require-parameters", func(t *testing.T) {
		tests := []struct {
			name    string
			schema  string
			version string
			types   []ExtensionType
		}{
			{"", "https://www.example.com/schema-my-favorite-sdo-1/v1/", "1.2.1", []ExtensionType{ExtensionTypeNewSDO}},
			{"New SDO 1", "", "1.2.1", []ExtensionType{ExtensionTypeNewSDO}},
			{"New SDO 1", "https://www.example.com/schema-my-favorite-sdo-1/v1/", "", []ExtensionType{ExtensionTypeNewSDO}},
			{"New SDO 1", "https://www.example.com/schema-my-favorite-sdo-1/v1/", "1.2.1", []ExtensionType{}},
		}
		for _, test := range tests {
			o, err := NewExtensionDefinition(test.name, test.schema, test.version, test.types)
			assert.Nil(o)
			assert.Equal(ErrInvalidParameter, err)
		}
	})

	t.Run("create", func(t *testing.T) {
		o, err := NewExtensionDefinition(
			"New SDO 1",
			"https://www.example.com/schema-my-favorite-sdo-1/v1/",
			"1.2.1",
			[]ExtensionType{ExtensionTypeNewSDO},
			OptionExtensionProperties([]string{"some-prop"}),
		)
		assert.NoError(err)
		assert.NotNil(o)
		assert.Contains(o.ExtensionProperties, "some-prop")
		assert.Equal(TypeExtensionDefinition, o.GetType())
		assert.NotNil(o.GetID())
		assert.NotNil(o.GetCreated())
		assert.NotNil(o.GetModified())
		assert.Nil(o.GetExtendedTopLevelProperties())
	})

	t.Run("json-parsing", func(t *testing.T) {
		var obj ExtensionDefinition
		err := json.Unmarshal([]byte(extPropJson), &obj)
		assert.NoError(err)
		assert.NotNil(obj)
		assert.Contains(obj.ExtensionTypes, ExtensionTypeNewSDO)
	})
}

func TestExtensionType(t *testing.T) {
	assert := assert.New(t)

	t.Run("parse-invalid", func(t *testing.T) {
		invalid := []byte(`{
			"id": "extension-definition--9c59fd79-4215-4ba2-920d-3e4f320e1e62",
			"type": "extension-definition",
			"spec_version": "2.1",
			"name": "New SDO 1",
			"description": "This schema creates a new object type called my-favorite-sdo-1",
			"created": "2014-02-20T09:16:08.989000Z",
			"modified": "2014-02-20T09:16:08.989000Z",
			"created_by_ref": "identity--11b76a96-5d2b-45e0-8a5a-f6994f370731",
			"schema": "https://www.example.com/schema-my-favorite-sdo-1/v1/",
			"version": "1.2.1",
			"extension_types": ["invalid-type"]
		  }
`)
		var obj ExtensionDefinition
		err := json.Unmarshal(invalid, &obj)
		assert.NoError(err)
		assert.Equal(ExtensionTypeInvalid, obj.ExtensionTypes[0])
	})

	t.Run("invalid-type-format", func(t *testing.T) {
		invalid := []byte(`{
			"id": "extension-definition--9c59fd79-4215-4ba2-920d-3e4f320e1e62",
			"type": "extension-definition",
			"spec_version": "2.1",
			"name": "New SDO 1",
			"description": "This schema creates a new object type called my-favorite-sdo-1",
			"created": "2014-02-20T09:16:08.989000Z",
			"modified": "2014-02-20T09:16:08.989000Z",
			"created_by_ref": "identity--11b76a96-5d2b-45e0-8a5a-f6994f370731",
			"schema": "https://www.example.com/schema-my-favorite-sdo-1/v1/",
			"version": "1.2.1",
			"extension_types": [1]
		  }
`)
		var obj ExtensionDefinition
		err := json.Unmarshal(invalid, &obj)
		assert.Error(err)
	})

	t.Run("Stringer", func(t *testing.T) {
		assert.Equal("new-sco", ExtensionTypeNewSCO.String())
	})
}

func TestSetExtensionsOption(t *testing.T) {
	assert := assert.New(t)

	t.Run("SDO", func(t *testing.T) {
		obj, err := NewAttackPattern("Some name", OptionExtension("extension-definition--9c59fd79-4215-4ba2-920d-3e4f320e1e62", extPropJson))
		assert.NoError(err)
		assert.NotNil(obj)
	})

	t.Run("SCO", func(t *testing.T) {
		obj, err := NewDomainName("example.com", OptionExtension("extension-definition--9c59fd79-4215-4ba2-920d-3e4f320e1e62", extPropJson))
		assert.NoError(err)
		assert.NotNil(obj)
	})

	t.Run("SRO", func(t *testing.T) {
		obj, err := NewRelationship(RelationshipTypeBasedOn, NewIdentifier(TypeArtifact), NewIdentifier(TypeFile), OptionExtension("extension-definition--9c59fd79-4215-4ba2-920d-3e4f320e1e62", extPropJson))
		assert.NoError(err)
		assert.NotNil(obj)
	})

	t.Run("Language", func(t *testing.T) {
		obj, err := NewLanguageContent(NewIdentifier(TypeArtifact), make(map[string]map[string]interface{}), OptionExtension("extension-definition--9c59fd79-4215-4ba2-920d-3e4f320e1e62", extPropJson))
		assert.NoError(err)
		assert.NotNil(obj)
	})

	t.Run("Markings", func(t *testing.T) {
		obj, err := NewMarkingDefinition("some new marking", "something", OptionExtension("extension-definition--9c59fd79-4215-4ba2-920d-3e4f320e1e62", extPropJson))
		assert.NoError(err)
		assert.NotNil(obj)
	})
}

func TestExtensionCustomObject(t *testing.T) {
	assert := assert.New(t)
	data := []byte(fmt.Sprintf("[%s,%s]", extPropJson, customObject))

	t.Run("Getters", func(t *testing.T) {
		custom := &CustomObject{}
		custom.Set("str", "str")
		custom.Set("int", int64(42))
		custom.Set("strSlice", []string{"1", "2"})
		custom.Set("modified", "20140220")

		assert.Equal("str", custom.GetAsString("str"))
		assert.Equal("", custom.GetAsString("str2"))
		assert.Equal(int64(42), custom.GetAsNumber("int"))
		assert.Equal(int64(0), custom.GetAsNumber("int2"))
		assert.Equal([]string{"1", "2"}, custom.GetAsStringSlice("strSlice"))
		assert.Nil(custom.GetAsStringSlice("strSlice2"))
		assert.Equal(STIXType(""), custom.GetType())
		assert.Nil(custom.GetCreated())
		assert.Nil(custom.GetModified())
	})

	t.Run("parse-no-handler", func(t *testing.T) {
		c, err := FromJSON(data)
		assert.NoError(err)
		assert.NotNil(c)
		obj := c.Get(Identifier("my-favorite-sdo--ac97aae4-83f1-46ca-a351-7aeb76678189"))
		assert.NotNil(obj)
		custom := obj.(*CustomObject)
		assert.Equal(STIXType("my-favorite-sdo"), custom.GetType())
		assert.Equal("value2", custom.Get("some_property_name2").(string))
		assert.Nil(custom.Get("does_not_exist"))
		assert.NotNil(custom.GetCreated())
		assert.NotNil(custom.GetModified())

		objects := c.GetAll(STIXType("my-favorite-sdo"))
		assert.NotNil(objects)
		assert.Len(objects, 1)

		noObjects := c.GetAll(STIXType("sdo-does-not-exist"))
		assert.Nil(noObjects)
	})

	t.Run("allow-ignoring-custom-objects", func(t *testing.T) {
		c, err := FromJSON(data, DropCustomOption())
		assert.NoError(err)

		obj := c.Get(Identifier("my-favorite-sdo--ac97aae4-83f1-46ca-a351-7aeb76678189"))
		assert.Nil(obj)
		assert.Len(c.ExtensionDefinitions(), 1)
	})

	t.Run("existing-STIX-object-with-extra-properties", func(t *testing.T) {
		data := []byte(fmt.Sprintf("[%s,%s]", extPropJson, sdoWithExtensionAttributes))
		c, err := FromJSON(data)
		assert.NoError(err)
		assert.NotNil(c)

		ind := c.Indicator(Identifier("indicator--e97bfccf-8970-4a3c-9cd1-5b5b97ed5d0c"))
		assert.NotNil(ind)
		e, ok := ind.Extensions["extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e"]
		assert.True(ok)
		assert.NotNil(e)

		ext := e.(*CustomObject)
		assert.Equal(int64(5), ext.GetAsNumber("rank"))
		assert.Equal(int64(8), ext.GetAsNumber("toxicity"))
		assert.Equal("property-extension", ext.GetAsString("extension_type"))
	})

	t.Run("check-some-attributes", func(t *testing.T) {
		obj := &CustomObject{}
		assert.Equal(Identifier(""), obj.GetID(), "should return empty string if not set")
		assert.Nil(obj.GetExtendedTopLevelProperties(), "should always return nil")
	})
}

func TestExtensionTopLevelProperties(t *testing.T) {
	assert := assert.New(t)
	data := []byte(fmt.Sprintf("[%s,%s,%s,%s,%s,%s]",
		extPropJson,
		sdoWithTopLevelAttributes,
		markingsWithTopLevelAttributes,
		languageWithTopLevelAttributes,
		scoWithTopLevelAttributes,
		sroWithTopLevelAttributes,
	))

	t.Run("parse-sdo-from-json", func(t *testing.T) {
		c, err := FromJSON(data)
		assert.NoError(err)
		assert.NotNil(c)

		obj := c.Indicator(Identifier("indicator--e97bfccf-8970-4a3c-9cd1-5b5b97ed5d0d"))
		assert.NotNil(obj)

		ext := obj.GetExtendedTopLevelProperties()
		assert.NotNil(ext)

		assert.Equal(int64(5), ext.GetAsNumber("rank"))
		assert.Equal(int64(8), ext.GetAsNumber("toxicity"))
	})

	t.Run("parse-sco-from-json", func(t *testing.T) {
		c, err := FromJSON(data)
		assert.NoError(err)
		assert.NotNil(c)

		obj := c.URL(Identifier("url--c1477287-23ac-5971-a010-5c287877fa60"))
		assert.NotNil(obj)

		ext := obj.GetExtendedTopLevelProperties()
		assert.NotNil(ext)

		assert.Equal(int64(5), ext.GetAsNumber("rank"))
		assert.Equal(int64(8), ext.GetAsNumber("toxicity"))
	})

	t.Run("parse-sro-from-json", func(t *testing.T) {
		c, err := FromJSON(data)
		assert.NoError(err)
		assert.NotNil(c)

		obj := c.Sighting(Identifier("sighting--ee20065d-2555-424f-ad9e-0f8428623c75"))
		assert.NotNil(obj)

		ext := obj.GetExtendedTopLevelProperties()
		assert.NotNil(ext)

		assert.Equal(int64(5), ext.GetAsNumber("rank"))
		assert.Equal(int64(8), ext.GetAsNumber("toxicity"))
	})

	t.Run("parse-marking-from-json", func(t *testing.T) {
		c, err := FromJSON(data)
		assert.NoError(err)
		assert.NotNil(c)

		obj := c.MarkingDefinition(Identifier("marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"))
		assert.NotNil(obj)

		ext := obj.GetExtendedTopLevelProperties()
		assert.NotNil(ext)

		assert.Equal(int64(5), ext.GetAsNumber("rank"))
		assert.Equal(int64(8), ext.GetAsNumber("toxicity"))
	})

	t.Run("parse-language-from-json", func(t *testing.T) {
		c, err := FromJSON(data)
		assert.NoError(err)
		assert.NotNil(c)

		obj := c.LanguageContent(Identifier("language-content--b86bd89f-98bb-4fa9-8cb2-9ad421da981d"))
		assert.NotNil(obj)

		ext := obj.GetExtendedTopLevelProperties()
		assert.NotNil(ext)

		assert.Equal(int64(5), ext.GetAsNumber("rank"))
		assert.Equal(int64(8), ext.GetAsNumber("toxicity"))
	})
}

const extPropJson = `{
	"id": "extension-definition--9c59fd79-4215-4ba2-920d-3e4f320e1e62",
	"type": "extension-definition",
	"spec_version": "2.1",
	"name": "New SDO 1",
	"description": "This schema creates a new object type called my-favorite-sdo-1",
	"created": "2014-02-20T09:16:08.989000Z",
	"modified": "2014-02-20T09:16:08.989000Z",
	"created_by_ref": "identity--11b76a96-5d2b-45e0-8a5a-f6994f370731",
	"schema": "https://www.example.com/schema-my-favorite-sdo-1/v1/",
	"version": "1.2.1",
	"extension_types": ["new-sdo"]
  }`

const customObject = `{
	"type": "my-favorite-sdo",
	"spec_version": "2.1",
	"id": "my-favorite-sdo--ac97aae4-83f1-46ca-a351-7aeb76678189",
	"created": "2014-02-20T09:16:08.989000Z",
	"modified": "2014-02-20T09:16:08.989000Z",
	"name": "This is the name of my favorite",
	"some_property_name1": "value1",
	"some_property_name2": "value2",
	"extensions": {
	  "extension-definition--9c59fd79-4215-4ba2-920d-3e4f320e1e62": {
		"extension_type": "new-sdo"
	  }
	}
  }`

const sdoWithExtensionAttributes = `{
	"type": "indicator",
	"spec_version": "2.1",
	"id": "indicator--e97bfccf-8970-4a3c-9cd1-5b5b97ed5d0c",
	"created": "2014-02-20T09:16:08.989000Z",
	"modified": "2014-02-20T09:16:08.989000Z",
	"name": "File hash for Poison Ivy variant",
	"description": "This file hash indicates that a sample of Poison Ivy is present.",
	"labels": ["malicious-activity"],
	"pattern": "[file:hashes.'SHA-256' = 'ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c']",
	"pattern_type": "stix",
	"valid_from": "2014-02-20T09:00:00.000000Z",
	"extensions": {
	  "extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e": {
		"extension_type": "property-extension",
		"rank": 5,
		"toxicity": 8
	  }
	}
  }`

const sdoWithTopLevelAttributes = `{
	"type": "indicator",
	"spec_version": "2.1",
	"id": "indicator--e97bfccf-8970-4a3c-9cd1-5b5b97ed5d0d",
	"created": "2014-02-20T09:16:08.989000Z",
	"modified": "2014-02-20T09:16:08.989000Z",
	"name": "File hash for Poison Ivy variant",
	"description": "This file hash indicates that a sample of Poison Ivy is present.",
	"labels": ["malicious-activity"],
	"pattern": "[file:hashes.'SHA-256' = 'ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c']",
	"pattern_type": "stix",
	"valid_from": "2014-02-20T09:00:00.000000Z",
	"rank": 5,
	"toxicity": 8,
	"extensions": {
	  "extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e": {
		"extension_type": "toplevel-property-extension"
	  }
	}
}`

const markingsWithTopLevelAttributes = `{
    "type": "marking-definition",
    "spec_version": "2.1",
    "id": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
    "created": "2016-08-01T00:00:00.000Z",
    "definition_type": "statement",
    "definition": {
      "statement": "Copyright 2019, Example Corp"
    },
	"rank": 5,
	"toxicity": 8,
	"extensions": {
	  "extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e": {
		"extension_type": "toplevel-property-extension"
	  }
	}
}`

const languageWithTopLevelAttributes = `{
    "type": "language-content",
    "id": "language-content--b86bd89f-98bb-4fa9-8cb2-9ad421da981d",
    "spec_version": "2.1",
    "created": "2017-02-08T21:31:22.007Z",
    "modified": "2017-02-08T21:31:22.007Z",
    "object_ref": "campaign--12a111f0-b824-4baf-a224-83b80237a094",
    "object_modified": "2017-02-08T21:31:22.007Z",
    "contents": {
      "de": {
        "name": "Bank Angriff",
        "description": "Weitere Informationen über Banküberfall"
      },
      "fr": {
        "name": "Attaque Bank",
        "description": "Plus d'informations sur la crise bancaire"
      }
    },
	"rank": 5,
	"toxicity": 8,
	"extensions": {
	  "extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e": {
		"extension_type": "toplevel-property-extension"
	  }
	}
}`

const scoWithTopLevelAttributes = `{
    "type": "url",
    "spec_version": "2.1",
    "id": "url--c1477287-23ac-5971-a010-5c287877fa60",
    "value": "https://example.com/research/index.html",
	"rank": 5,
	"toxicity": 8,
	"extensions": {
	  "extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e": {
		"extension_type": "toplevel-property-extension"
	  }
	}
}`

const sroWithTopLevelAttributes = `{
    "type": "sighting",
    "spec_version": "2.1",
    "id": "sighting--ee20065d-2555-424f-ad9e-0f8428623c75",
    "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
    "created": "2016-04-06T20:08:31.000Z",
    "modified": "2016-04-06T20:08:31.000Z",
    "first_seen": "2015-12-21T19:00:00Z",
    "last_seen": "2015-12-21T19:00:00Z",
    "count": 50,
    "sighting_of_ref": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
    "observed_data_refs": [
      "observed-data--b67d30ff-02ac-498a-92f9-32f845f448cf"
    ],
    "where_sighted_refs": ["identity--b67d30ff-02ac-498a-92f9-32f845f448ff"],
	"rank": 5,
	"toxicity": 8,
	"extensions": {
	  "extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e": {
		"extension_type": "toplevel-property-extension"
	  }
	}
}`
