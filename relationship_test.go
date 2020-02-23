// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRelationship(t *testing.T) {
	assert := assert.New(t)

	source := NewIdentifier(TypeIPv4Addr)
	target := NewIdentifier(TypeIndicator)
	typ := RelationshipTypeRelatedTo

	t.Run("stringer", func(t *testing.T) {
		assert.Equal("related-to", RelationshipTypeRelatedTo.String())
	})

	t.Run("missing_property", func(t *testing.T) {
		r, err := NewRelationship(0, "", "", nil)
		assert.Nil(r)
		assert.Equal(ErrPropertyMissing, err)
	})

	t.Run("no_optional", func(t *testing.T) {
		r, err := NewRelationship(typ, source, target, nil)
		assert.NotNil(r)
		assert.NoError(err)
	})

	t.Run("with_options", func(t *testing.T) {
		conf := 50
		desc := "My description"
		ts := &Timestamp{time.Now()}
		createdBy := NewIdentifier(TypeIdentity)
		ref := &ExternalReference{}
		marking := &GranularMarking{}
		labels := []string{"tag1", "tag2"}
		lang := "en"
		objmark := []Identifier{Identifier("id")}
		specVer := "2.0"

		opts := []RelationshipOption{
			RelationshipOptionConfidence(conf),
			RelationshipOptionDesciption(desc),
			RelationshipOptionCreated(ts),
			RelationshipOptionModified(ts),
			RelationshipOptionCreatedBy(createdBy),
			RelationshipOptionExternalReferences([]*ExternalReference{ref}),
			RelationshipOptionGranularMarking(marking),
			RelationshipOptionLabels(labels),
			RelationshipOptionLang(lang),
			RelationshipOptionObjectMarking(objmark),
			RelationshipOptionRevoked(true),
			RelationshipOptionSpecVersion(specVer),
			RelationshipOptionStartTime(ts),
			RelationshipOptionStopTime(ts),
		}
		r, err := NewRelationship(typ, source, target, opts...)
		assert.NotNil(r)
		assert.NoError(err)
		assert.Equal(conf, r.Confidence)
		assert.Equal(desc, r.Description)
		assert.Equal(ts, r.Created)
		assert.Equal(ts, r.Modified)
		assert.Equal(ts, r.StartTime)
		assert.Equal(ts, r.StopTime)
		assert.Equal(createdBy, r.CreatedBy)
		assert.Contains(r.ExternalReferences, ref)
		assert.Equal(marking, r.GranularMarking)
		assert.Equal(labels, r.Labels)
		assert.Equal(lang, r.Lang)
		assert.Equal(objmark, r.ObjectMarking)
		assert.True(r.Revoked)
		assert.Equal(specVer, r.SpecVersion)
	})

	t.Run("parse-JSON", func(t *testing.T) {
		data := []byte(
			`
{
      "type": "relationship",
      "id": "relationship--6598bf44-1c10-4218-af9f-75b5b71c23a7",
      "created": "2015-05-15T09:00:00.000Z",
      "modified": "2015-05-15T09:00:00.000Z",
      "object_marking_refs": [
        "marking-definition--3444e29e-2aa6-46f7-a01c-1c174820fa67"
      ],
      "relationship_type": "uses",
      "source_ref": "threat-actor--6d179234-61fc-40c4-ae86-3d53308d8e65",
      "target_ref": "malware--2485b844-4efe-4343-84c8-eb33312dd56f"
}
`)
		var rel Relationship
		err := json.Unmarshal(data, &rel)
		assert.NoError(err)
		assert.Equal(RelationshipTypeUses, rel.RelationshipType)
	})
}

func TestRelationshipType(t *testing.T) {
	assert := assert.New(t)
	t.Run("valid", func(t *testing.T) {
		data, err := RelationshipTypeBelongsTo.MarshalJSON()
		assert.NoError(err)
		assert.Equal(`"belongs-to"`, string(data))

		var actual RelationshipType
		ptr := &actual
		err = ptr.UnmarshalJSON([]byte(`"belongs-to"`))
		assert.NoError(err)
		assert.Equal(RelationshipTypeBelongsTo, actual)
	})
	t.Run("invalid", func(t *testing.T) {
		var actual RelationshipType
		ptr := &actual
		err := ptr.UnmarshalJSON([]byte(`"AAAAAA"`))
		assert.NoError(err)
		assert.Equal(RelationshipTypeUnknown, actual)
	})
	t.Run("invalid-short", func(t *testing.T) {
		var actual RelationshipType
		ptr := &actual
		err := ptr.UnmarshalJSON([]byte(`A`))
		assert.NoError(err)
		assert.Equal(RelationshipTypeUnknown, actual)
	})
}
