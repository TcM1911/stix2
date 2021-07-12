// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDirectory(t *testing.T) {
	assert := assert.New(t)

	pth := "/root"
	pthEnc := "ascii"
	ts := &Timestamp{time.Now()}
	contains := []Identifier{Identifier("some")}

	t.Run("missing_property", func(t *testing.T) {
		obj, err := NewDirectory("")
		assert.Nil(obj)
		assert.Equal(ErrInvalidParameter, err)
	})

	t.Run("with_property", func(t *testing.T) {
		obj, err := NewDirectory(pth, nil)
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
			//
			OptionPathEncoding(pthEnc),
			OptionCtime(ts),
			OptionMtime(ts),
			OptionAtime(ts),
			OptionContains(contains),
		}
		obj, err := NewDirectory(pth, opts...)
		assert.NotNil(obj)
		assert.NoError(err)
		assert.Equal(marking, obj.GranularMarking)
		assert.Equal(objmark, obj.ObjectMarking)
		assert.Equal(specVer, obj.SpecVersion)
		assert.True(obj.Defanged)

		assert.Equal(pth, obj.Path)
		assert.Equal(pthEnc, obj.PathEnc)
		assert.Equal(ts, obj.Ctime)
		assert.Equal(ts, obj.Mtime)
		assert.Equal(ts, obj.Atime)
		assert.Equal(contains, obj.Contains)
	})

	t.Run("id-generation", func(t *testing.T) {
		tests := []struct {
			path string
			id   string
		}{
			{`C:\\Windows\\System32`, "directory--4ba604fb-ee79-5983-bc76-49018d75c428"},
		}
		for _, test := range tests {
			obj, err := NewDirectory(test.path)
			assert.NoError(err)
			assert.Equal(Identifier(test.id), obj.ID)
		}
	})

	t.Run("parse_json", func(t *testing.T) {
		data := []byte(`{
  "type": "directory",
  "spec_version": "2.1",
  "id": "directory--93c0a9b0-520d-545d-9094-1a08ddf46b05",
  "path": "C:\\Windows\\System32"
}`)
		var obj *Directory
		err := json.Unmarshal(data, &obj)
		assert.NoError(err)
		assert.Equal(Identifier("directory--93c0a9b0-520d-545d-9094-1a08ddf46b05"), obj.ID)
		assert.Equal("2.1", obj.SpecVersion)
		assert.Equal(TypeDirectory, obj.Type)
		assert.Equal("C:\\Windows\\System32", obj.Path)
	})
}
