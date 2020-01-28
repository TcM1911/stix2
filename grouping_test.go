// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestGrouping(t *testing.T) {
	assert := assert.New(t)

	context := "New campaign"
	objects := []Identifier{Identifier("1")}

	t.Run("missing_property", func(t *testing.T) {
		obj, err := NewGrouping("", []Identifier{})
		assert.Nil(obj)
		assert.Equal(ErrPropertyMissing, err)
	})

	t.Run("no_optional", func(t *testing.T) {
		obj, err := NewGrouping(context, objects, nil)
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

		desc := "My description"
		name := "Group 1"

		opts := []GroupingOption{
			GroupingOptionConfidence(conf),
			GroupingOptionCreated(ts),
			GroupingOptionModified(ts),
			GroupingOptionCreatedBy(createdBy),
			GroupingOptionExternalReferences([]*ExternalReference{ref}),
			GroupingOptionGranularMarking(marking),
			GroupingOptionLables(lables),
			GroupingOptionLang(lang),
			GroupingOptionObjectMarking(objmark),
			GroupingOptionRevoked(true),
			GroupingOptionSpecVersion(specVer),
			//
			GroupingOptionDesciption(desc),
			GroupingOptionName(name),
		}
		obj, err := NewGrouping(context, objects, opts...)
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

		assert.Equal(desc, obj.Description)
		assert.Equal(name, obj.Name)
	})

	t.Run("parse_json", func(t *testing.T) {
		data := []byte(`{
  "type": "grouping",
  "spec_version": "2.1",
  "id": "grouping--84e4d88f-44ea-4bcd-bbf3-b2c1c320bcb3",
  "created_by_ref": "identity--a463ffb3-1bd9-4d94-b02d-74e4f1658283",
  "created": "2015-12-21T19:59:11.000Z",
  "modified": "2015-12-21T19:59:11.000Z",
  "name": "The Black Vine Cyberespionage Group",
  "description": "A simple collection of Black Vine Cyberespionage Group attributed intel",
  "context": "suspicious-activity",
  "object_refs": [
    "indicator--26ffb872-1dd9-446e-b6f5-d58527e5b5d2",
    "campaign--83422c77-904c-4dc1-aff5-5c38f3a2c55c",
    "relationship--f82356ae-fe6c-437c-9c24-6b64314ae68a",
    "file--0203b5c8-f8b6-4ddb-9ad0-527d727f968b"
  ]
}`)
		ts, err := time.Parse(time.RFC3339Nano, "2015-12-21T19:59:11.000Z")
		assert.NoError(err)
		var obj *Grouping
		err = json.Unmarshal(data, &obj)
		assert.NoError(err)
		assert.Equal(Identifier("grouping--84e4d88f-44ea-4bcd-bbf3-b2c1c320bcb3"), obj.ID)
		assert.Equal("2.1", obj.SpecVersion)
		assert.Equal(TypeGrouping, obj.Type)
		assert.Equal("The Black Vine Cyberespionage Group", obj.Name)
		assert.Equal("A simple collection of Black Vine Cyberespionage Group attributed intel", obj.Description)
		assert.Equal(ts, obj.Created.Time)
		assert.Equal(ts, obj.Modified.Time)
		assert.Equal(GroupingContextSuspiciousActivity, obj.Context)
		assert.Len(obj.Objects, 4)
		assert.Contains(obj.Objects, Identifier("indicator--26ffb872-1dd9-446e-b6f5-d58527e5b5d2"))
		assert.Contains(obj.Objects, Identifier("campaign--83422c77-904c-4dc1-aff5-5c38f3a2c55c"))
		assert.Contains(obj.Objects, Identifier("relationship--f82356ae-fe6c-437c-9c24-6b64314ae68a"))
		assert.Contains(obj.Objects, Identifier("file--0203b5c8-f8b6-4ddb-9ad0-527d727f968b"))
	})
}
