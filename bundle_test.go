// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBundle(t *testing.T) {
	assert := assert.New(t)
	data := []byte(
		`
{
  "type": "bundle",
  "id": "bundle--5d0092c5-5f74-4287-9642-33f4c354e56d",
  "objects": [
    {
      "type": "indicator",
      "spec_version": "2.1",
      "id": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
      "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
      "created": "2016-04-29T14:09:00.000Z",
      "modified": "2016-04-29T14:09:00.000Z",
      "object_marking_refs": ["marking-definition--089a6ecb-cc15-43cc-9494-767639779123"],
      "name": "Poison Ivy Malware",
      "description": "This file is part of Poison Ivy",
      "pattern": "[file:hashes.'SHA-256' = 'aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f']"
    }
  ]
}
`)
	var bundle Bundle
	err := json.Unmarshal(data, &bundle)

	assert.NoError(err)
	assert.Len(bundle.Objects, 1)

	var typ Indicator
	err = json.Unmarshal(bundle.Objects[0], &typ)
	assert.NoError(err)
	assert.Equal("Poison Ivy Malware", typ.Name)
}

func TestCreateBundle(t *testing.T) {
	assert := assert.New(t)
	ipStr := "10.0.0.1"
	ip, err := NewIPv4Address(ipStr)
	assert.NoError(err)

	b, err := NewBundle(ip)
	assert.NoError(err)
	assert.NotNil(b)

	data, err := json.Marshal(b)
	assert.NoError(err)
	assert.Contains(string(data), `"type":"ipv4-addr","id":"ipv4-addr--8e9dc7c8-b845-5cfb-9c37-cff3a18e08d6","spec_version":"2.1","value":"10.0.0.1"`)
}
