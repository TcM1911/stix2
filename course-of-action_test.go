// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCourseOfAction(t *testing.T) {
	assert := assert.New(t)

	name := "New campaign"

	t.Run("missing_property", func(t *testing.T) {
		obj, err := NewCourseOfAction("")
		assert.Nil(obj)
		assert.Equal(ErrPropertyMissing, err)
	})

	t.Run("no_optional", func(t *testing.T) {
		obj, err := NewCourseOfAction(name, nil)
		assert.NotNil(obj)
		assert.NoError(err)
	})

	t.Run("with_options", func(t *testing.T) {
		conf := 50
		desc := "My description"
		ts := &Timestamp{time.Now()}
		createdBy := NewIdentifier(TypeIdentity)
		ref := &ExternalReference{}
		marking := make([]*GranularMarking, 0)
		labels := []string{"tag1", "tag2"}
		lang := "en"
		objmark := []Identifier{Identifier("id")}
		specVer := "2.0"

		opts := []CourseOfActionOption{
			CourseOfActionOptionConfidence(conf),
			CourseOfActionOptionCreated(ts),
			CourseOfActionOptionModified(ts),
			CourseOfActionOptionCreatedBy(createdBy),
			CourseOfActionOptionExternalReferences([]*ExternalReference{ref}),
			CourseOfActionOptionGranularMarking(marking),
			CourseOfActionOptionLabels(labels),
			CourseOfActionOptionLang(lang),
			CourseOfActionOptionObjectMarking(objmark),
			CourseOfActionOptionRevoked(true),
			CourseOfActionOptionSpecVersion(specVer),
			//
			CourseOfActionOptionDescription(desc),
		}
		obj, err := NewCourseOfAction(name, opts...)
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
	})

	t.Run("parse_json", func(t *testing.T) {
		data := []byte(
			`
{
"type": "course-of-action",
"spec_version": "2.1",
"id": "course-of-action--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
"created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
"created": "2016-04-06T20:03:48.000Z",
"modified": "2016-04-06T20:03:48.000Z",
"name": "Add TCP port 80 Filter Rule to the existing Block UDP 1434 Filter",
"description": "This is how to add a filter rule to block inbound access to TCP port 80 to the existing UDP 1434 filter ..."
}
`)
		ts, err := time.Parse(time.RFC3339Nano, "2016-04-06T20:03:48.000Z")
		assert.NoError(err)
		var obj *CourseOfAction
		err = json.Unmarshal(data, &obj)
		assert.NoError(err)
		assert.Equal(Identifier("course-of-action--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"), obj.ID)
		assert.Equal("2.1", obj.SpecVersion)
		assert.Equal(TypeCourseOfAction, obj.Type)
		assert.Equal("Add TCP port 80 Filter Rule to the existing Block UDP 1434 Filter", obj.Name)
		assert.Equal("This is how to add a filter rule to block inbound access to TCP port 80 to the existing UDP 1434 filter ...", obj.Description)
		assert.Equal(ts, obj.Created.Time)
		assert.Equal(ts, obj.Modified.Time)
	})
}

func TestCourseOfActionMitigates(t *testing.T) {
	assert := assert.New(t)

	t.Run("attack-pattern", func(t *testing.T) {
		obj, err := NewCourseOfAction("name")
		assert.NoError(err)
		id := NewIdentifier(TypeAttackPattern)
		rel, err := obj.AddMitigates(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(obj.ID, rel.Source)
	})

	t.Run("indicator", func(t *testing.T) {
		obj, err := NewCourseOfAction("name")
		assert.NoError(err)
		id := NewIdentifier(TypeIndicator)
		rel, err := obj.AddMitigates(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(obj.ID, rel.Source)
	})

	t.Run("malware", func(t *testing.T) {
		obj, err := NewCourseOfAction("name")
		assert.NoError(err)
		id := NewIdentifier(TypeMalware)
		rel, err := obj.AddMitigates(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(obj.ID, rel.Source)
	})

	t.Run("tool", func(t *testing.T) {
		obj, err := NewCourseOfAction("name")
		assert.NoError(err)
		id := NewIdentifier(TypeTool)
		rel, err := obj.AddMitigates(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(obj.ID, rel.Source)
	})

	t.Run("vulnerability", func(t *testing.T) {
		obj, err := NewCourseOfAction("name")
		assert.NoError(err)
		id := NewIdentifier(TypeVulnerability)
		rel, err := obj.AddMitigates(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(obj.ID, rel.Source)
	})

	t.Run("invalid_type", func(t *testing.T) {
		obj, err := NewCourseOfAction("name")
		assert.NoError(err)
		id := NewIdentifier(TypeIPv4Addr)
		rel, err := obj.AddMitigates(id)
		assert.Equal(err, ErrInvalidParameter)
		assert.Nil(rel)
	})
}

func TestCourseOfActionRemediates(t *testing.T) {
	assert := assert.New(t)

	t.Run("malware", func(t *testing.T) {
		obj, err := NewCourseOfAction("name")
		assert.NoError(err)
		id := NewIdentifier(TypeMalware)
		rel, err := obj.AddRemediates(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(obj.ID, rel.Source)
	})

	t.Run("vulnerability", func(t *testing.T) {
		obj, err := NewCourseOfAction("name")
		assert.NoError(err)
		id := NewIdentifier(TypeVulnerability)
		rel, err := obj.AddRemediates(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(obj.ID, rel.Source)
	})

	t.Run("invalid_type", func(t *testing.T) {
		obj, err := NewCourseOfAction("name")
		assert.NoError(err)
		id := NewIdentifier(TypeIPv4Addr)
		rel, err := obj.AddRemediates(id)
		assert.Equal(err, ErrInvalidParameter)
		assert.Nil(rel)
	})
}

func TestCourseOfActionAddInvestigates(t *testing.T) {
	assert := assert.New(t)

	t.Run("location", func(t *testing.T) {
		obj, err := NewCourseOfAction("name")
		assert.NoError(err)
		id := NewIdentifier(TypeIndicator)
		rel, err := obj.AddInvestigates(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(obj.ID, rel.Source)
	})

	t.Run("invalid_type", func(t *testing.T) {
		obj, err := NewCourseOfAction("name")
		assert.NoError(err)
		id := NewIdentifier(TypeIPv4Addr)
		rel, err := obj.AddInvestigates(id)
		assert.Equal(err, ErrInvalidParameter)
		assert.Nil(rel)
	})
}
