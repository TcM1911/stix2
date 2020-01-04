// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSighting(t *testing.T) {
	assert := assert.New(t)

	data, err := NewIdentifier(TypeIPv4Addr)
	assert.NoError(err)
	indicator, err := NewIdentifier(TypeIndicator)
	assert.NoError(err)

	t.Run("missing_property", func(t *testing.T) {
		r, err := NewSighting("")
		assert.Nil(r)
		assert.Equal(ErrPropertyMissing, err)
	})

	t.Run("no_optional", func(t *testing.T) {
		r, err := NewSighting(indicator, nil)
		assert.NotNil(r)
		assert.NoError(err)
	})

	t.Run("with_options", func(t *testing.T) {
		conf := 50
		desc := "My description"
		ts := &Timestamp{time.Now()}
		createdBy, err := NewIdentifier(TypeIdentity)
		assert.NoError(err)
		ref := &ExternalReference{}
		marking := &GranularMarking{}
		lables := []string{"tag1", "tag2"}
		lang := "en"
		objmark := []Identifier{Identifier("id")}
		specVer := "2.0"

		count := int64(50)
		obsData := []Identifier{data}
		ws := []Identifier{createdBy}

		opts := []SightingOption{
			SightingOptionConfidence(conf),
			SightingOptionDesciption(desc),
			SightingOptionCreated(ts),
			SightingOptionModified(ts),
			SightingOptionCreatedBy(createdBy),
			SightingOptionExternalReferences([]*ExternalReference{ref}),
			SightingOptionGranularMarking(marking),
			SightingOptionLables(lables),
			SightingOptionLang(lang),
			SightingOptionObjectMarking(objmark),
			SightingOptionRevoked(true),
			SightingOptionSpecVersion(specVer),
			SightingOptionFirstSeen(ts),
			SightingOptionLastSeen(ts),
			SightingOptionCount(count),
			SightingOptionObservedData(obsData),
			SightingOptionWhereSighted(ws),
			SightingOptionSummary(true),
		}
		r, err := NewSighting(indicator, opts...)
		assert.NotNil(r)
		assert.NoError(err)
		assert.Equal(conf, r.Confidence)
		assert.Equal(desc, r.Description)
		assert.Equal(ts, r.Created)
		assert.Equal(ts, r.Modified)
		assert.Equal(ts, r.FirstSeen)
		assert.Equal(ts, r.LastSeen)
		assert.Equal(createdBy, r.CreatedBy)
		assert.Contains(r.ExternalReferences, ref)
		assert.Equal(marking, r.GranularMarking)
		assert.Equal(lables, r.Lables)
		assert.Equal(lang, r.Lang)
		assert.Equal(objmark, r.ObjectMarking)
		assert.True(r.Revoked)
		assert.Equal(specVer, r.SpecVersion)

		assert.Equal(count, r.Count)
		assert.Equal(obsData, r.ObservedData)
		assert.Equal(ws, r.WhereSighted)
		assert.True(r.Summary)
	})

	t.Run("validate_count", func(t *testing.T) {
		tests := []struct {
			count int64
			err   bool
		}{
			{int64(-1), true},
			{int64(0), false},
			{int64(100), false},
			{int64(999999999), false},
			{int64(999999999 + 1), true},
		}
		for _, test := range tests {
			obj, err := NewSighting(indicator, SightingOptionCount(test.count))
			if test.err {
				assert.Error(err)
				assert.Nil(obj)
			} else {
				assert.NoError(err)
				assert.NotNil(obj)
			}
		}
	})

	t.Run("validate_first_last_seen", func(t *testing.T) {
		early := &Timestamp{time.Now()}
		later := &Timestamp{early.Add(10 * time.Second)}
		tests := []struct {
			before *Timestamp
			after  *Timestamp
			err    bool
		}{
			{early, later, false},
			{early, early, false},
			{later, early, true},
		}
		for _, test := range tests {
			obj, err := NewSighting(indicator, SightingOptionFirstSeen(test.before), SightingOptionLastSeen(test.after))
			if test.err {
				assert.Error(err)
				assert.Nil(obj)
			} else {
				assert.NoError(err)
				assert.NotNil(obj)
			}
		}
	})

	t.Run("json_parsing", func(t *testing.T) {
		ct, err := time.Parse(time.RFC3339Nano, "2016-04-06T20:08:31.000Z")
		assert.NoError(err)
		mt, err := time.Parse(time.RFC3339Nano, "2016-04-06T20:08:31.000Z")
		assert.NoError(err)
		data := []byte(`{
			"type": "sighting", "spec_version": "2.1", "id":
  			"sighting--ee20065d-2555-424f-ad9e-0f8428623c75", "created_by_ref":
  			"identity--f431f809-377b-45e0-aa1c-6a4751cae5ff", "created":
  			"2016-04-06T20:08:31.000Z", "modified": "2016-04-06T20:08:31.000Z",
  			"sighting_of_ref": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"}`)
		var obj *Sighting
		err = json.Unmarshal(data, &obj)
		assert.NoError(err)
		assert.Equal(TypeSighting, obj.Type)
		assert.Equal("2.1", obj.SpecVersion)
		assert.Equal(Identifier("sighting--ee20065d-2555-424f-ad9e-0f8428623c75"), obj.ID)
		assert.Equal(Identifier("identity--f431f809-377b-45e0-aa1c-6a4751cae5ff"), obj.CreatedBy)
		assert.Equal(ct, obj.Created.Time)
		assert.Equal(mt, obj.Modified.Time)
		assert.Equal(Identifier("indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"), obj.SightingOf)
	})
}
