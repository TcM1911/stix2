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
  }
`
