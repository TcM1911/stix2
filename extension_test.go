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
