// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestObservedData(t *testing.T) {
	assert := assert.New(t)

	first := &Timestamp{}
	last := &Timestamp{}
	count := int64(10)
	objs := []Identifier{Identifier("1"), Identifier("2")}

	t.Run("missing_property", func(t *testing.T) {
		obj, err := NewObservedData(nil, nil, int64(0), []Identifier{}, nil)
		assert.Nil(obj)
		assert.Equal(ErrPropertyMissing, err)
	})

	t.Run("no_optional", func(t *testing.T) {
		obj, err := NewObservedData(first, last, count, objs, nil)
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

		opts := []ObservedDataOption{
			ObservedDataOptionConfidence(conf),
			ObservedDataOptionCreated(ts),
			ObservedDataOptionModified(ts),
			ObservedDataOptionCreatedBy(createdBy),
			ObservedDataOptionExternalReferences([]*ExternalReference{ref}),
			ObservedDataOptionGranularMarking(marking),
			ObservedDataOptionLabels(labels),
			ObservedDataOptionLang(lang),
			ObservedDataOptionObjectMarking(objmark),
			ObservedDataOptionRevoked(true),
			ObservedDataOptionSpecVersion(specVer),
		}
		obj, err := NewObservedData(first, last, count, objs, opts...)
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

		assert.Equal(first, obj.FirstObserved)
		assert.Equal(last, obj.LastObserved)
		assert.Equal(count, obj.NumberObserved)
		assert.Equal(objs, obj.ObjectRefs)
	})

	t.Run("parse_json", func(t *testing.T) {
		data := []byte(`{
  "type": "observed-data",
  "spec_version": "2.1",
  "id": "observed-data--b67d30ff-02ac-498a-92f9-32f845f448cf",
  "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
  "created": "2016-04-06T19:58:16.000Z",
  "modified": "2016-04-06T19:58:16.000Z",
  "first_observed": "2015-12-21T19:00:00Z",
  "last_observed": "2015-12-21T19:00:00Z",
  "number_observed": 50,
  "object_refs": [
    "ipv4-address--efcd5e80-570d-4131-b213-62cb18eaa6a8",
    "domain-name--ecb120bf-2694-4902-a737-62b74539a41b"
  ]
}`)
		ts, err := time.Parse(time.RFC3339Nano, "2016-04-06T19:58:16.000Z")
		assert.NoError(err)
		first, _ := time.Parse(time.RFC3339Nano, "2015-12-21T19:00:00Z")
		last, _ := time.Parse(time.RFC3339Nano, "2015-12-21T19:00:00Z")
		var obj *ObservedData
		err = json.Unmarshal(data, &obj)
		assert.NoError(err)
		assert.Equal(Identifier("observed-data--b67d30ff-02ac-498a-92f9-32f845f448cf"), obj.ID)
		assert.Equal("2.1", obj.SpecVersion)
		assert.Equal(TypeObservedData, obj.Type)
		assert.Equal(ts, obj.Created.Time)
		assert.Equal(ts, obj.Modified.Time)
		assert.Equal(first, obj.FirstObserved.Time)
		assert.Equal(last, obj.LastObserved.Time)
		assert.Contains(obj.ObjectRefs, Identifier("ipv4-address--efcd5e80-570d-4131-b213-62cb18eaa6a8"))
		assert.Contains(obj.ObjectRefs, Identifier("domain-name--ecb120bf-2694-4902-a737-62b74539a41b"))
		assert.Equal(int64(50), obj.NumberObserved)
	})
}
