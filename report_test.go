// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestReport(t *testing.T) {
	assert := assert.New(t)

	ts := &Timestamp{time.Now()}
	desc := "Report content"
	objects := []Identifier{Identifier("something")}
	name := "Report name"

	t.Run("missing_property", func(t *testing.T) {
		obj, err := NewReport("", nil, []Identifier{}, nil)
		assert.Nil(obj)
		assert.Equal(ErrPropertyMissing, err)
	})

	t.Run("no_optional", func(t *testing.T) {
		obj, err := NewReport(name, ts, objects, nil)
		assert.NotNil(obj)
		assert.NoError(err)
	})

	t.Run("with_options", func(t *testing.T) {
		conf := 50
		createdBy := NewIdentifier(TypeIdentity)
		ref := &ExternalReference{}
		marking := make([]*GranularMarking, 0)
		labels := []string{"tag1", "tag2"}
		lang := "en"
		objmark := []Identifier{Identifier("id")}
		specVer := "2.0"

		typs := []string{ReportTypeAttackPattern}

		opts := []STIXOption{
			OptionConfidence(conf),
			OptionCreated(ts),
			OptionModified(ts),
			OptionCreatedBy(createdBy),
			OptionExternalReferences([]*ExternalReference{ref}),
			OptionGranularMarking(marking),
			OptionLabels(labels),
			OptionLang(lang),
			OptionObjectMarking(objmark),
			OptionRevoked(true),
			OptionSpecVersion(specVer),
			//
			OptionDescription(desc),
			OptionTypes(typs),
		}
		obj, err := NewReport(name, ts, objects, opts...)
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

		assert.Equal(desc, obj.Description)
		assert.Equal(name, obj.Name)
		assert.Equal(typs, obj.Types)
		assert.Equal(objects, obj.Objects)
		assert.Equal(ts, obj.Published)
	})

	t.Run("parse_json", func(t *testing.T) {
		data := []byte(`{
  "type": "report",
  "spec_version": "2.1",
  "id": "report--84e4d88f-44ea-4bcd-bbf3-b2c1c320bcb3",
  "created_by_ref": "identity--a463ffb3-1bd9-4d94-b02d-74e4f1658283",
  "created": "2015-12-21T19:59:11.000Z",
  "modified": "2015-12-21T19:59:11.000Z",
  "name": "The Black Vine Cyberespionage Group",
  "description": "A simple report with an indicator and campaign",
  "published": "2016-01-20T17:00:00.000Z",
  "report_types": ["campaign"],
  "object_refs": [
    "indicator--26ffb872-1dd9-446e-b6f5-d58527e5b5d2",
    "campaign--83422c77-904c-4dc1-aff5-5c38f3a2c55c",
    "relationship--f82356ae-fe6c-437c-9c24-6b64314ae68a"
  ]
}`)
		ts, err := time.Parse(time.RFC3339Nano, "2015-12-21T19:59:11.000Z")
		assert.NoError(err)
		pub, err := time.Parse(time.RFC3339Nano, "2016-01-20T17:00:00.000Z")
		assert.NoError(err)
		var obj *Report
		err = json.Unmarshal(data, &obj)
		assert.NoError(err)
		assert.Equal(Identifier("report--84e4d88f-44ea-4bcd-bbf3-b2c1c320bcb3"), obj.ID)
		assert.Equal("2.1", obj.SpecVersion)
		assert.Equal(TypeReport, obj.Type)
		assert.Equal(ts, obj.Created.Time)
		assert.Equal(ts, obj.Modified.Time)
		assert.Equal(pub, obj.Published.Time)
		assert.Equal([]string{ReportTypeCampaign}, obj.Types)
		assert.Equal("A simple report with an indicator and campaign", obj.Description)
		assert.Equal("The Black Vine Cyberespionage Group", obj.Name)
		assert.Contains(obj.Objects, Identifier("indicator--26ffb872-1dd9-446e-b6f5-d58527e5b5d2"))
		assert.Contains(obj.Objects, Identifier("campaign--83422c77-904c-4dc1-aff5-5c38f3a2c55c"))
		assert.Contains(obj.Objects, Identifier("relationship--f82356ae-fe6c-437c-9c24-6b64314ae68a"))
		assert.Equal(Identifier("identity--a463ffb3-1bd9-4d94-b02d-74e4f1658283"), obj.CreatedBy)
	})
}
