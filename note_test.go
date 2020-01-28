// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNote(t *testing.T) {
	assert := assert.New(t)

	content := "Note content"
	authors := []string{"Author 1", "Author 2"}
	abstract := "Note abstract"
	ip := NewIdentifier(TypeIPv4Addr)
	objects := []Identifier{ip}

	t.Run("missing_property", func(t *testing.T) {
		obj, err := NewNote("", []Identifier{}, nil)
		assert.Nil(obj)
		assert.Equal(ErrPropertyMissing, err)
	})

	t.Run("no_optional", func(t *testing.T) {
		obj, err := NewNote(content, objects, nil)
		assert.NotNil(obj)
		assert.NoError(err)
	})

	t.Run("with_options", func(t *testing.T) {
		conf := 50
		ts := &Timestamp{time.Now()}
		createdBy := NewIdentifier(TypeIdentity)
		ref := &ExternalReference{}
		marking := &GranularMarking{}
		lables := []string{"tag1", "tag2"}
		lang := "en"
		objmark := []Identifier{Identifier("id")}
		specVer := "2.0"

		opts := []NoteOption{
			NoteOptionConfidence(conf),
			NoteOptionCreated(ts),
			NoteOptionModified(ts),
			NoteOptionCreatedBy(createdBy),
			NoteOptionExternalReferences([]*ExternalReference{ref}),
			NoteOptionGranularMarking(marking),
			NoteOptionLables(lables),
			NoteOptionLang(lang),
			NoteOptionObjectMarking(objmark),
			NoteOptionRevoked(true),
			NoteOptionSpecVersion(specVer),
			//
			NoteOptionAbstract(abstract),
			NoteOptionAuthors(authors),
		}
		obj, err := NewNote(content, objects, opts...)
		assert.NotNil(obj)
		assert.NoError(err)
		assert.Equal(conf, obj.Confidence)
		assert.Equal(ts, obj.Created)
		assert.Equal(ts, obj.Modified)
		assert.Equal(createdBy, obj.CreatedBy)
		assert.Contains(obj.ExternalReferences, ref)
		assert.Equal(marking, obj.GranularMarking)
		assert.Equal(lables, obj.Lables)
		assert.Equal(lang, obj.Lang)
		assert.Equal(objmark, obj.ObjectMarking)
		assert.True(obj.Revoked)
		assert.Equal(specVer, obj.SpecVersion)

		assert.Equal(abstract, obj.Abstract)
		assert.Equal(authors, obj.Authors)
	})

	t.Run("parse_json", func(t *testing.T) {
		data := []byte(`{
  "type": "note",
  "spec_version": "2.1",
  "id": "note--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061",
  "created": "2016-05-12T08:17:27.000Z",
  "modified": "2016-05-12T08:17:27.000Z",
  "external_references": [
    {
      "source_name": "job-tracker",
      "external_id": "job-id-1234"
    }
  ],
  "abstract": "Tracking Team Note#1",
  "content": "This note indicates the various steps taken by the threat analyst team to investigate this specific campaign. Step 1) Do a scan 2) Review scanned results for identified hosts not known by external intel….etc",
  "authors": ["John Doe"],
  "object_refs": ["campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"]
}`)
		ts, err := time.Parse(time.RFC3339Nano, "2016-05-12T08:17:27.000Z")
		assert.NoError(err)
		var obj *Note
		err = json.Unmarshal(data, &obj)
		assert.NoError(err)
		assert.Equal(Identifier("note--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061"), obj.ID)
		assert.Equal("2.1", obj.SpecVersion)
		assert.Equal(TypeNote, obj.Type)
		assert.Equal(ts, obj.Created.Time)
		assert.Equal(ts, obj.Modified.Time)
		assert.Equal("Tracking Team Note#1", obj.Abstract)
		assert.Equal("This note indicates the various steps taken by the threat analyst team to investigate this specific campaign. Step 1) Do a scan 2) Review scanned results for identified hosts not known by external intel….etc", obj.Content)
		assert.Contains(obj.Authors, "John Doe")
		assert.Contains(obj.Objects, Identifier("campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"))
		assert.Len(obj.ExternalReferences, 1)
		assert.Equal("job-tracker", obj.ExternalReferences[0].Name)
		assert.Equal("job-id-1234", obj.ExternalReferences[0].ExternalID)
	})
}
