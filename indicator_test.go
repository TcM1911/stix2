// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestIndicator(t *testing.T) {
	assert := assert.New(t)

	pattern := "new pattern"
	patternType := "stix"
	ts := &Timestamp{time.Now()}

	t.Run("missing_property", func(t *testing.T) {
		obj, err := NewIndicator("", "", nil)
		assert.Nil(obj)
		assert.Equal(ErrPropertyMissing, err)
	})

	t.Run("no_optional", func(t *testing.T) {
		obj, err := NewIndicator(pattern, patternType, ts, nil)
		assert.NotNil(obj)
		assert.NoError(err)
	})

	t.Run("with_options", func(t *testing.T) {
		conf := 50
		desc := "My description"
		ts := &Timestamp{time.Now()}
		createdBy := NewIdentifier(TypeIndicator)
		ref := &ExternalReference{}
		marking := make([]*GranularMarking, 0)
		labels := []string{"tag1", "tag2"}
		lang := "en"
		objmark := []Identifier{Identifier("id")}
		specVer := "2.0"

		name := "Name"
		indType := []string{IndicatorTypeCompromised}
		patVer := "1.0"
		kchain := []*KillChainPhase{{}}

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
			OptionName(name),
			OptionTypes(indType),
			OptionKillChainPhase(kchain),
			OptionPatternVersion(patVer),
			OptionValidUntil(ts),
		}
		obj, err := NewIndicator(pattern, patternType, ts, opts...)
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
		assert.Equal(indType, obj.Types)
		assert.Equal(kchain, obj.KillChainPhase)
		assert.Equal(ts, obj.ValidUntil)
		assert.Equal(patVer, obj.PatternVersion)
	})

	t.Run("parse_json", func(t *testing.T) {
		data := []byte(`{
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
    "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
    "created": "2016-04-06T20:03:48.000Z",
    "modified": "2016-04-06T20:03:48.000Z",
    "indicator_types": ["malicious-activity"],
    "name": "Poison Ivy Malware",
    "description": "This file is part of Poison Ivy",
    "pattern": "[ file:hashes.'SHA-256' = '4bac27393bdd9777ce02453256c5577cd02275510b2227f473d03f533924f877' ]",
    "valid_from": "2016-01-01T00:00:00Z"
  }`)
		ts, err := time.Parse(time.RFC3339Nano, "2016-04-06T20:03:48.000Z")
		assert.NoError(err)
		var obj *Indicator
		err = json.Unmarshal(data, &obj)
		assert.NoError(err)
		assert.Equal(Identifier("indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"), obj.ID)
		assert.Equal("2.1", obj.SpecVersion)
		assert.Equal(TypeIndicator, obj.Type)
		assert.Equal("Poison Ivy Malware", obj.Name)
		assert.Equal(ts, obj.Created.Time)
		assert.Equal(ts, obj.Modified.Time)
		assert.Equal("This file is part of Poison Ivy", obj.Description)
		assert.Equal("[ file:hashes.'SHA-256' = '4bac27393bdd9777ce02453256c5577cd02275510b2227f473d03f533924f877' ]", obj.Pattern)
		assert.Contains(obj.Types, IndicatorTypeMaliciousActivity)
	})
}

func TestIndicatorIndicates(t *testing.T) {
	assert := assert.New(t)
	pattern := "new pattern"
	patternType := "stix"
	ts := &Timestamp{time.Now()}

	t.Run("attack-pattern", func(t *testing.T) {
		obj, err := NewIndicator(pattern, patternType, ts)
		assert.NoError(err)
		id := NewIdentifier(TypeAttackPattern)
		rel, err := obj.AddIndicates(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(obj.ID, rel.Source)
	})

	t.Run("campaign", func(t *testing.T) {
		obj, err := NewIndicator(pattern, patternType, ts)
		assert.NoError(err)
		id := NewIdentifier(TypeCampaign)
		rel, err := obj.AddIndicates(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(obj.ID, rel.Source)
	})

	t.Run("infrastructure", func(t *testing.T) {
		obj, err := NewIndicator(pattern, patternType, ts)
		assert.NoError(err)
		id := NewIdentifier(TypeInfrastructure)
		rel, err := obj.AddIndicates(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(obj.ID, rel.Source)
	})

	t.Run("intrusion-set", func(t *testing.T) {
		obj, err := NewIndicator(pattern, patternType, ts)
		assert.NoError(err)
		id := NewIdentifier(TypeIntrusionSet)
		rel, err := obj.AddIndicates(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(obj.ID, rel.Source)
	})

	t.Run("malware", func(t *testing.T) {
		obj, err := NewIndicator(pattern, patternType, ts)
		assert.NoError(err)
		id := NewIdentifier(TypeMalware)
		rel, err := obj.AddIndicates(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(obj.ID, rel.Source)
	})

	t.Run("threat-actor", func(t *testing.T) {
		obj, err := NewIndicator(pattern, patternType, ts)
		assert.NoError(err)
		id := NewIdentifier(TypeThreatActor)
		rel, err := obj.AddIndicates(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(obj.ID, rel.Source)
	})

	t.Run("tool", func(t *testing.T) {
		obj, err := NewIndicator(pattern, patternType, ts)
		assert.NoError(err)
		id := NewIdentifier(TypeTool)
		rel, err := obj.AddIndicates(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(obj.ID, rel.Source)
	})

	t.Run("invalid_type", func(t *testing.T) {
		obj, err := NewIndicator(pattern, patternType, ts)
		assert.NoError(err)
		id := NewIdentifier(TypeIPv4Addr)
		rel, err := obj.AddIndicates(id)
		assert.Equal(err, ErrInvalidParameter)
		assert.Nil(rel)
	})
}

func TestIndicatorBasedOn(t *testing.T) {
	assert := assert.New(t)
	pattern := "new pattern"
	patternType := "stix"
	ts := &Timestamp{time.Now()}

	t.Run("observed-data", func(t *testing.T) {
		obj, err := NewIndicator(pattern, patternType, ts)
		assert.NoError(err)
		id := NewIdentifier(TypeObservedData)
		rel, err := obj.AddBasedOn(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(obj.ID, rel.Source)
	})

	t.Run("invalid_type", func(t *testing.T) {
		obj, err := NewIndicator(pattern, patternType, ts)
		assert.NoError(err)
		id := NewIdentifier(TypeIPv4Addr)
		rel, err := obj.AddBasedOn(id)
		assert.Equal(err, ErrInvalidParameter)
		assert.Nil(rel)
	})
}
