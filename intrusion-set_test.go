// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestIntrusionSet(t *testing.T) {
	assert := assert.New(t)

	name := "new name"

	t.Run("missing_property", func(t *testing.T) {
		obj, err := NewIntrusionSet("")
		assert.Nil(obj)
		assert.Equal(ErrPropertyMissing, err)
	})

	t.Run("no_optional", func(t *testing.T) {
		obj, err := NewIntrusionSet(name, nil)
		assert.NotNil(obj)
		assert.NoError(err)
	})

	t.Run("with_options", func(t *testing.T) {
		conf := 50
		desc := "My description"
		ts := &Timestamp{time.Now()}
		createdBy := NewIdentifier(TypeIntrusionSet)
		ref := &ExternalReference{}
		marking := &GranularMarking{}
		lables := []string{"tag1", "tag2"}
		lang := "en"
		objmark := []Identifier{Identifier("id")}
		specVer := "2.0"

		aliases := []string{"1", "2"}
		goals := []string{"goal1", "goal2"}
		rl := AttackResourceLevelIndividual
		pm := AttackMotivationIdeology
		sm := AttackMotivationPersonalGain

		opts := []IntrusionSetOption{
			IntrusionSetOptionConfidence(conf),
			IntrusionSetOptionCreated(ts),
			IntrusionSetOptionModified(ts),
			IntrusionSetOptionCreatedBy(createdBy),
			IntrusionSetOptionExternalReferences([]*ExternalReference{ref}),
			IntrusionSetOptionGranularMarking(marking),
			IntrusionSetOptionLables(lables),
			IntrusionSetOptionLang(lang),
			IntrusionSetOptionObjectMarking(objmark),
			IntrusionSetOptionRevoked(true),
			IntrusionSetOptionSpecVersion(specVer),
			//
			IntrusionSetOptionDesciption(desc),
			IntrusionSetOptionGoals(goals),
			IntrusionSetOptionAliases(aliases),
			IntrusionSetOptionFirstSeen(ts),
			IntrusionSetOptionLastSeen(ts),
			IntrusionSetOptionResourceLevel(rl),
			IntrusionSetOptionPrimaryMotivation(pm),
			IntrusionSetOptionSecondaryMotivation(sm),
		}
		obj, err := NewIntrusionSet(name, opts...)
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
		assert.Equal(name, obj.Name)

		assert.Equal(desc, obj.Description)
		assert.Equal(goals, obj.Goals)
		assert.Equal(ts, obj.FirstSeen)
		assert.Equal(ts, obj.LastSeen)
		assert.Equal(aliases, obj.Aliases)
		assert.Equal(rl, obj.ResourceLevel)
		assert.Equal(pm, obj.PrimaryMotivation)
		assert.Equal(sm, obj.SecondaryMotivation)
	})

	t.Run("parse_json", func(t *testing.T) {
		data := []byte(`{
  "type": "intrusion-set",
  "spec_version": "2.1",
  "id": "intrusion-set--4e78f46f-a023-4e5f-bc24-71b3ca22ec29",
  "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
  "created": "2016-04-06T20:03:48.000Z",
  "modified": "2016-04-06T20:03:48.000Z",
  "name": "Bobcat Breakin",
  "description": "Incidents usually feature a shared TTP of a bobcat being released within the building containing network access, scaring users to leave their computers without locking them first. Still determining where the threat actors are getting the bobcats.",
  "aliases": ["Zookeeper"],
  "goals": ["acquisition-theft", "harassment", "damage"]
}`)
		ts, err := time.Parse(time.RFC3339Nano, "2016-04-06T20:03:48.000Z")
		assert.NoError(err)
		var obj *IntrusionSet
		err = json.Unmarshal(data, &obj)
		assert.NoError(err)
		assert.Equal(Identifier("intrusion-set--4e78f46f-a023-4e5f-bc24-71b3ca22ec29"), obj.ID)
		assert.Equal("2.1", obj.SpecVersion)
		assert.Equal(TypeIntrusionSet, obj.Type)
		assert.Equal("Bobcat Breakin", obj.Name)
		assert.Equal(ts, obj.Created.Time)
		assert.Equal(ts, obj.Modified.Time)
		assert.Contains(obj.Aliases, "Zookeeper")
		assert.Contains(obj.Goals, "acquisition-theft")
		assert.Contains(obj.Goals, "harassment")
		assert.Contains(obj.Goals, "damage")
	})
}

func TestIntrusionSetAttributedTo(t *testing.T) {
	assert := assert.New(t)
	name := "new name"

	t.Run("threat-actor", func(t *testing.T) {
		obj, err := NewIntrusionSet(name)
		assert.NoError(err)
		id := NewIdentifier(TypeThreatActor)
		rel, err := obj.AddAttributedTo(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(obj.ID, rel.Source)
		assert.Equal(RelationshipTypeAttrubutedTo, rel.RelationshipType)
	})

	t.Run("invalid_type", func(t *testing.T) {
		obj, err := NewIntrusionSet(name)
		assert.NoError(err)
		id := NewIdentifier(TypeIPv4Addr)
		rel, err := obj.AddAttributedTo(id)
		assert.Equal(err, ErrInvalidParameter)
		assert.Nil(rel)
	})
}

func TestIntrusionSetCompromises(t *testing.T) {
	assert := assert.New(t)
	name := "new name"

	t.Run("infrastructure", func(t *testing.T) {
		obj, err := NewIntrusionSet(name)
		assert.NoError(err)
		id := NewIdentifier(TypeInfrastructure)
		rel, err := obj.AddCompromises(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(obj.ID, rel.Source)
		assert.Equal(RelationshipTypeCompromises, rel.RelationshipType)
	})

	t.Run("invalid_type", func(t *testing.T) {
		obj, err := NewIntrusionSet(name)
		assert.NoError(err)
		id := NewIdentifier(TypeIPv4Addr)
		rel, err := obj.AddCompromises(id)
		assert.Equal(err, ErrInvalidParameter)
		assert.Nil(rel)
	})
}

func TestIntrusionSetHosts(t *testing.T) {
	assert := assert.New(t)
	name := "new name"

	t.Run("infrastructure", func(t *testing.T) {
		obj, err := NewIntrusionSet(name)
		assert.NoError(err)
		id := NewIdentifier(TypeInfrastructure)
		rel, err := obj.AddHosts(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(obj.ID, rel.Source)
		assert.Equal(RelationshipTypeHosts, rel.RelationshipType)
	})

	t.Run("invalid_type", func(t *testing.T) {
		obj, err := NewIntrusionSet(name)
		assert.NoError(err)
		id := NewIdentifier(TypeIPv4Addr)
		rel, err := obj.AddHosts(id)
		assert.Equal(err, ErrInvalidParameter)
		assert.Nil(rel)
	})
}

func TestIntrusionSetOwns(t *testing.T) {
	assert := assert.New(t)
	name := "new name"

	t.Run("infrastructure", func(t *testing.T) {
		obj, err := NewIntrusionSet(name)
		assert.NoError(err)
		id := NewIdentifier(TypeInfrastructure)
		rel, err := obj.AddOwns(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(obj.ID, rel.Source)
		assert.Equal(RelationshipTypeOwns, rel.RelationshipType)
	})

	t.Run("invalid_type", func(t *testing.T) {
		obj, err := NewIntrusionSet(name)
		assert.NoError(err)
		id := NewIdentifier(TypeIPv4Addr)
		rel, err := obj.AddOwns(id)
		assert.Equal(err, ErrInvalidParameter)
		assert.Nil(rel)
	})
}

func TestIntrusionSetOriginatesFrom(t *testing.T) {
	assert := assert.New(t)
	name := "new name"

	t.Run("location", func(t *testing.T) {
		obj, err := NewIntrusionSet(name)
		assert.NoError(err)
		id := NewIdentifier(TypeLocation)
		rel, err := obj.AddOriginatesFrom(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(obj.ID, rel.Source)
		assert.Equal(RelationshipTypeOriginatesFrom, rel.RelationshipType)
	})

	t.Run("invalid_type", func(t *testing.T) {
		obj, err := NewIntrusionSet(name)
		assert.NoError(err)
		id := NewIdentifier(TypeIPv4Addr)
		rel, err := obj.AddOriginatesFrom(id)
		assert.Equal(err, ErrInvalidParameter)
		assert.Nil(rel)
	})
}

func TestIntrusionSetTargets(t *testing.T) {
	assert := assert.New(t)
	name := "new name"

	t.Run("identity", func(t *testing.T) {
		obj, err := NewIntrusionSet(name)
		assert.NoError(err)
		id := NewIdentifier(TypeIdentity)
		rel, err := obj.AddTargets(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(obj.ID, rel.Source)
		assert.Equal(RelationshipTypeTargets, rel.RelationshipType)
	})

	t.Run("vulnerability", func(t *testing.T) {
		obj, err := NewIntrusionSet(name)
		assert.NoError(err)
		id := NewIdentifier(TypeVulnerability)
		rel, err := obj.AddTargets(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(obj.ID, rel.Source)
		assert.Equal(RelationshipTypeTargets, rel.RelationshipType)
	})

	t.Run("location", func(t *testing.T) {
		obj, err := NewIntrusionSet(name)
		assert.NoError(err)
		id := NewIdentifier(TypeLocation)
		rel, err := obj.AddTargets(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(obj.ID, rel.Source)
		assert.Equal(RelationshipTypeTargets, rel.RelationshipType)
	})

	t.Run("invalid_type", func(t *testing.T) {
		obj, err := NewIntrusionSet(name)
		assert.NoError(err)
		id := NewIdentifier(TypeIPv4Addr)
		rel, err := obj.AddTargets(id)
		assert.Equal(err, ErrInvalidParameter)
		assert.Nil(rel)
	})
}

func TestIntrusionSetUses(t *testing.T) {
	assert := assert.New(t)
	name := "new name"

	t.Run("attack-pattern", func(t *testing.T) {
		obj, err := NewIntrusionSet(name)
		assert.NoError(err)
		id := NewIdentifier(TypeAttackPattern)
		rel, err := obj.AddUses(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(obj.ID, rel.Source)
		assert.Equal(RelationshipTypeUses, rel.RelationshipType)
	})

	t.Run("malware", func(t *testing.T) {
		obj, err := NewIntrusionSet(name)
		assert.NoError(err)
		id := NewIdentifier(TypeMalware)
		rel, err := obj.AddUses(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(obj.ID, rel.Source)
		assert.Equal(RelationshipTypeUses, rel.RelationshipType)
	})

	t.Run("infrastructure", func(t *testing.T) {
		obj, err := NewIntrusionSet(name)
		assert.NoError(err)
		id := NewIdentifier(TypeInfrastructure)
		rel, err := obj.AddUses(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(obj.ID, rel.Source)
		assert.Equal(RelationshipTypeUses, rel.RelationshipType)
	})

	t.Run("tool", func(t *testing.T) {
		obj, err := NewIntrusionSet(name)
		assert.NoError(err)
		id := NewIdentifier(TypeTool)
		rel, err := obj.AddUses(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(obj.ID, rel.Source)
		assert.Equal(RelationshipTypeUses, rel.RelationshipType)
	})

	t.Run("invalid_type", func(t *testing.T) {
		obj, err := NewIntrusionSet(name)
		assert.NoError(err)
		id := NewIdentifier(TypeIPv4Addr)
		rel, err := obj.AddUses(id)
		assert.Equal(err, ErrInvalidParameter)
		assert.Nil(rel)
	})
}
