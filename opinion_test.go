// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestOpinion(t *testing.T) {
	assert := assert.New(t)

	expl := "Opinion content"
	authors := []string{"Author 1", "Author 2"}
	objects := []Identifier{Identifier("something")}
	val := OpinionAgree

	t.Run("missing_property", func(t *testing.T) {
		obj, err := NewOpinion(OpinionValue(0), []Identifier{}, nil)
		assert.Nil(obj)
		assert.Equal(ErrPropertyMissing, err)
	})

	t.Run("no_optional", func(t *testing.T) {
		obj, err := NewOpinion(val, objects, nil)
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
		lang := "en"
		objmark := []Identifier{Identifier("id")}
		specVer := "2.0"

		opts := []OpinionOption{
			OpinionOptionConfidence(conf),
			OpinionOptionCreated(ts),
			OpinionOptionModified(ts),
			OpinionOptionCreatedBy(createdBy),
			OpinionOptionExternalReferences([]*ExternalReference{ref}),
			OpinionOptionGranularMarking(marking),
			OpinionOptionLabels(labels),
			OpinionOptionLang(lang),
			OpinionOptionObjectMarking(objmark),
			OpinionOptionRevoked(true),
			OpinionOptionSpecVersion(specVer),
			//
			OpinionOptionExplanation(expl),
			OpinionOptionAuthors(authors),
		}
		obj, err := NewOpinion(val, objects, opts...)
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

		assert.Equal(expl, obj.Explanation)
		assert.Equal(authors, obj.Authors)
		assert.Equal(val, obj.Value)
		assert.Equal(objects, obj.Objects)
	})

	t.Run("parse_json", func(t *testing.T) {
		data := []byte(`{
    "type": "opinion",
    "spec_version": "2.1",
    "id": "opinion--b01efc25-77b4-4003-b18b-f6e24b5cd9f7",
    "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
    "created": "2016-05-12T08:17:27.000Z",
    "modified": "2016-05-12T08:17:27.000Z",
    "object_refs": ["relationship--16d2358f-3b0d-4c88-b047-0da2f7ed4471"],
    "opinion": "strongly-disagree",
    "explanation": "This doesn't seem like it is feasible. We've seen how PandaCat has attacked Spanish infrastructure over the last 3 years, so this change in targeting seems too great to be viable. The methods used are more commonly associated with the FlameDragonCrew."
  }`)
		ts, err := time.Parse(time.RFC3339Nano, "2016-05-12T08:17:27.000Z")
		assert.NoError(err)
		var obj *Opinion
		err = json.Unmarshal(data, &obj)
		assert.NoError(err)
		assert.Equal(Identifier("opinion--b01efc25-77b4-4003-b18b-f6e24b5cd9f7"), obj.ID)
		assert.Equal("2.1", obj.SpecVersion)
		assert.Equal(TypeOpinion, obj.Type)
		assert.Equal(ts, obj.Created.Time)
		assert.Equal(ts, obj.Modified.Time)
		assert.Equal(OpinionStronglyDisagree, obj.Value)
		assert.Equal("This doesn't seem like it is feasible. We've seen how PandaCat has attacked Spanish infrastructure over the last 3 years, so this change in targeting seems too great to be viable. The methods used are more commonly associated with the FlameDragonCrew.", obj.Explanation)
		assert.Contains(obj.Objects, Identifier("relationship--16d2358f-3b0d-4c88-b047-0da2f7ed4471"))
		assert.Equal(Identifier("identity--f431f809-377b-45e0-aa1c-6a4751cae5ff"), obj.CreatedBy)
	})
}

func TestOpinionValue(t *testing.T) {
	assert := assert.New(t)

	t.Run("stringer", func(t *testing.T) {
		tests := []struct {
			op  OpinionValue
			str string
		}{
			{OpinionStronglyDisagree, "strongly-disagree"},
			{OpinionDisagree, "disagree"},
			{OpinionNeutral, "neutral"},
			{OpinionAgree, "agree"},
			{OpinionStronglyAgree, "strongly-agree"},
			{OpinionValue(0), ""},
		}
		for _, test := range tests {
			assert.Equal(test.str, test.op.String())
		}
	})

	t.Run("unmarshalJSON", func(t *testing.T) {
		tests := []struct {
			op  OpinionValue
			str []byte
		}{
			{OpinionStronglyDisagree, []byte("\"strongly-disagree\"")},
			{OpinionDisagree, []byte("\"disagree\"")},
			{OpinionNeutral, []byte("\"neutral\"")},
			{OpinionAgree, []byte("\"agree\"")},
			{OpinionStronglyAgree, []byte("\"strongly-agree\"")},
			{OpinionValue(0), []byte("\"\"")},
		}
		for _, test := range tests {
			var val OpinionValue
			vp := &val
			err := vp.UnmarshalJSON(test.str)
			assert.NoError(err)
			assert.Equal(test.op, val)
		}
	})
}
