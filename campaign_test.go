// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCampaign(t *testing.T) {
	assert := assert.New(t)

	name := "New campaign"

	t.Run("missing_property", func(t *testing.T) {
		obj, err := NewCampaign("")
		assert.Nil(obj)
		assert.Equal(ErrPropertyMissing, err)
	})

	t.Run("no_optional", func(t *testing.T) {
		obj, err := NewCampaign(name, nil)
		assert.NotNil(obj)
		assert.NoError(err)
	})

	t.Run("with_options", func(t *testing.T) {
		conf := 50
		desc := "My description"
		ts := &Timestamp{time.Now()}
		createdBy := NewIdentifier(TypeIdentity)
		ref := &ExternalReference{}
		marking := &GranularMarking{}
		lables := []string{"tag1", "tag2"}
		lang := "en"
		objmark := []Identifier{Identifier("id")}
		specVer := "2.0"

		aliases := []string{"name1", "name2"}
		objective := "Campaign objective"

		opts := []CampaignOption{
			CampaignOptionConfidence(conf),
			CampaignOptionCreated(ts),
			CampaignOptionModified(ts),
			CampaignOptionCreatedBy(createdBy),
			CampaignOptionExternalReferences([]*ExternalReference{ref}),
			CampaignOptionGranularMarking(marking),
			CampaignOptionLables(lables),
			CampaignOptionLang(lang),
			CampaignOptionObjectMarking(objmark),
			CampaignOptionRevoked(true),
			CampaignOptionSpecVersion(specVer),
			//
			CampaignOptionDesciption(desc),
			CampaignOptionAliases(aliases),
			CampaignOptionFirstSeen(ts),
			CampaignOptionLastSeen(ts),
			CampaignOptionObjective(objective),
		}
		obj, err := NewCampaign(name, opts...)
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
		assert.Equal(aliases, obj.Aliases)
		assert.Equal(ts, obj.FirstSeen)
		assert.Equal(ts, obj.LastSeen)
		assert.Equal(objective, obj.Objective)
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
			obj, err := NewCampaign(name, CampaignOptionFirstSeen(test.before), CampaignOptionLastSeen(test.after))
			if test.err {
				assert.Error(err)
				assert.Nil(obj)
			} else {
				assert.NoError(err)
				assert.NotNil(obj)
			}
		}
	})

	t.Run("parse_json", func(t *testing.T) {
		data := []byte(`{
  "type": "campaign",
  "spec_version": "2.1",
  "id": "campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
  "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
  "created": "2016-04-06T20:03:00.000Z",
  "modified": "2016-04-06T20:03:00.000Z",
  "name": "Green Group Attacks Against Finance",
  "description": "Campaign by Green Group against a series of targets in the financial services sector."
}`)
		ts, err := time.Parse(time.RFC3339Nano, "2016-04-06T20:03:00.000Z")
		assert.NoError(err)
		var obj *Campaign
		err = json.Unmarshal(data, &obj)
		assert.NoError(err)
		assert.Equal(Identifier("campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"), obj.ID)
		assert.Equal("2.1", obj.SpecVersion)
		assert.Equal(TypeCampaign, obj.Type)
		assert.Equal("Green Group Attacks Against Finance", obj.Name)
		assert.Equal("Campaign by Green Group against a series of targets in the financial services sector.", obj.Description)
		assert.Equal(ts, obj.Created.Time)
		assert.Equal(ts, obj.Modified.Time)
	})
}

func TestCampaignAddTargets(t *testing.T) {
	assert := assert.New(t)

	t.Run("identity", func(t *testing.T) {
		obj, err := NewCampaign("name")
		assert.NoError(err)
		id := NewIdentifier(TypeIdentity)
		rel, err := obj.AddTargets(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(obj.ID, rel.Source)
	})

	t.Run("location", func(t *testing.T) {
		obj, err := NewCampaign("name")
		assert.NoError(err)
		id := NewIdentifier(TypeLocation)
		rel, err := obj.AddTargets(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(obj.ID, rel.Source)
	})

	t.Run("identity", func(t *testing.T) {
		obj, err := NewCampaign("name")
		assert.NoError(err)
		id := NewIdentifier(TypeVulnerability)
		rel, err := obj.AddTargets(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(obj.ID, rel.Source)
	})

	t.Run("invalid_type", func(t *testing.T) {
		obj, err := NewCampaign("name")
		assert.NoError(err)
		id := NewIdentifier(TypeIPv4Addr)
		rel, err := obj.AddTargets(id)
		assert.Equal(err, ErrInvalidParameter)
		assert.Nil(rel)
	})
}

func TestCampaignAddUses(t *testing.T) {
	assert := assert.New(t)

	t.Run("malware", func(t *testing.T) {
		obj, err := NewCampaign("name")
		assert.NoError(err)
		id := NewIdentifier(TypeMalware)
		rel, err := obj.AddUses(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(obj.ID, rel.Source)
	})

	t.Run("tool", func(t *testing.T) {
		obj, err := NewCampaign("name")
		assert.NoError(err)
		id := NewIdentifier(TypeTool)
		rel, err := obj.AddUses(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(obj.ID, rel.Source)
	})

	t.Run("invalid_type", func(t *testing.T) {
		obj, err := NewCampaign("name")
		assert.NoError(err)
		id := NewIdentifier(TypeIPv4Addr)
		rel, err := obj.AddUses(id)
		assert.Equal(err, ErrInvalidParameter)
		assert.Nil(rel)
	})
}

func TestCampaignAttributedTo(t *testing.T) {
	assert := assert.New(t)

	t.Run("intrusion-set", func(t *testing.T) {
		obj, err := NewCampaign("name")
		assert.NoError(err)
		id := NewIdentifier(TypeIntrusionSet)
		rel, err := obj.AddAttributedTo(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(obj.ID, rel.Source)
	})

	t.Run("threat-actor", func(t *testing.T) {
		obj, err := NewCampaign("name")
		assert.NoError(err)
		id := NewIdentifier(TypeThreatActor)
		rel, err := obj.AddAttributedTo(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(obj.ID, rel.Source)
	})

	t.Run("invalid_type", func(t *testing.T) {
		obj, err := NewCampaign("name")
		assert.NoError(err)
		id := NewIdentifier(TypeIPv4Addr)
		rel, err := obj.AddAttributedTo(id)
		assert.Equal(err, ErrInvalidParameter)
		assert.Nil(rel)
	})
}

func TestCampaignAddCompromises(t *testing.T) {
	assert := assert.New(t)

	t.Run("infrastructure", func(t *testing.T) {
		obj, err := NewCampaign("name")
		assert.NoError(err)
		id := NewIdentifier(TypeInfrastructure)
		rel, err := obj.AddCompromises(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(obj.ID, rel.Source)
	})

	t.Run("invalid_type", func(t *testing.T) {
		obj, err := NewCampaign("name")
		assert.NoError(err)
		id := NewIdentifier(TypeIPv4Addr)
		rel, err := obj.AddCompromises(id)
		assert.Equal(err, ErrInvalidParameter)
		assert.Nil(rel)
	})
}

func TestCampaignAddOriginatesFrom(t *testing.T) {
	assert := assert.New(t)

	t.Run("location", func(t *testing.T) {
		obj, err := NewCampaign("name")
		assert.NoError(err)
		id := NewIdentifier(TypeLocation)
		rel, err := obj.AddOriginatesFrom(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(obj.ID, rel.Source)
	})

	t.Run("invalid_type", func(t *testing.T) {
		obj, err := NewCampaign("name")
		assert.NoError(err)
		id := NewIdentifier(TypeIPv4Addr)
		rel, err := obj.AddOriginatesFrom(id)
		assert.Equal(err, ErrInvalidParameter)
		assert.Nil(rel)
	})
}
