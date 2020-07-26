// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestThreatActor(t *testing.T) {
	assert := assert.New(t)

	ts := &Timestamp{time.Now()}
	desc := "ThreatActor content"
	name := "ThreatActor name"
	alias := []string{"Name 1"}
	roles := []string{ThreatActorRoleIndependent}
	goals := []string{"money"}
	soph := ThreatActorSophisticationMinimal
	reso := AttackResourceLevelIndividual
	prim := AttackMotivationPersonalGain
	secd := []string{AttackMotivationRevenge}
	pers := []string{AttackMotivationPersonalSatisfaction}

	t.Run("missing_property", func(t *testing.T) {
		obj, err := NewThreatActor("", nil)
		assert.Nil(obj)
		assert.Equal(ErrPropertyMissing, err)
	})

	t.Run("no_optional", func(t *testing.T) {
		obj, err := NewThreatActor(name, nil)
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

		typs := []string{ThreatActorTypeCriminal}

		opts := []ThreatActorOption{
			ThreatActorOptionConfidence(conf),
			ThreatActorOptionCreated(ts),
			ThreatActorOptionModified(ts),
			ThreatActorOptionCreatedBy(createdBy),
			ThreatActorOptionExternalReferences([]*ExternalReference{ref}),
			ThreatActorOptionGranularMarking(marking),
			ThreatActorOptionLabels(labels),
			ThreatActorOptionLang(lang),
			ThreatActorOptionObjectMarking(objmark),
			ThreatActorOptionRevoked(true),
			ThreatActorOptionSpecVersion(specVer),
			//
			ThreatActorOptionDescription(desc),
			ThreatActorOptionTypes(typs),
			ThreatActorOptionAliases(alias),
			ThreatActorOptionFirstSeen(ts),
			ThreatActorOptionLastSeen(ts),
			ThreatActorOptionRoles(roles),
			ThreatActorOptionGoals(goals),
			ThreatActorOptionSophistication(soph),
			ThreatActorOptionResourceLevel(reso),
			ThreatActorOptionPrimaryMotivation(prim),
			ThreatActorOptionSecondaryMotivations(secd),
			ThreatActorOptionPersonalMotivations(pers),
		}
		obj, err := NewThreatActor(name, opts...)
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
		assert.Equal(ts, obj.FirstSeen)
		assert.Equal(ts, obj.LastSeen)
		assert.Equal(alias, obj.Aliases)
		assert.Equal(roles, obj.Roles)
		assert.Equal(goals, obj.Goals)
		assert.Equal(soph, obj.Sophistication)
		assert.Equal(reso, obj.ResourceLevel)
		assert.Equal(prim, obj.PrimaryMotivation)
		assert.Equal(secd, obj.SecondaryMotivations)
		assert.Equal(pers, obj.PersonalMotivations)
	})

	t.Run("parse_json", func(t *testing.T) {
		data := []byte(`{
  "type": "threat-actor",
  "spec_version": "2.1",
  "id": "threat-actor--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
  "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
  "created": "2016-04-06T20:03:48.000Z",
  "modified": "2016-04-06T20:03:48.000Z",
  "threat_actor_types": [ "crime-syndicate"],
  "name": "Evil Org",
  "description": "The Evil Org threat actor group",
  "aliases": ["Syndicate 1", "Evil Syndicate 99"],
  "roles": ["director"],
  "goals": ["Steal bank money", "Steal credit cards"],
  "sophistication": "advanced",
  "resource_level": "team",
  "primary_motivation": "organizational-gain"
}`)
		ts, err := time.Parse(time.RFC3339Nano, "2016-04-06T20:03:48.000Z")
		assert.NoError(err)
		var obj *ThreatActor
		err = json.Unmarshal(data, &obj)
		assert.NoError(err)
		assert.Equal(Identifier("threat-actor--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"), obj.ID)
		assert.Equal("2.1", obj.SpecVersion)
		assert.Equal(TypeThreatActor, obj.Type)
		assert.Equal(ts, obj.Created.Time)
		assert.Equal(ts, obj.Modified.Time)
		assert.Equal("Evil Org", obj.Name)
		assert.Contains(obj.Types, ThreatActorTypeCrimeSyndicate)
		assert.Contains(obj.Roles, ThreatActorRoleDirector)
		assert.Equal(ThreatActorSophisticationAdvanced, obj.Sophistication)
	})
}

func TestThreatActorAttributedTo(t *testing.T) {
	assert := assert.New(t)
	name := "ThreatActor name"

	t.Run("identity", func(t *testing.T) {
		a, err := NewThreatActor(name)
		assert.NoError(err)
		id := NewIdentifier(TypeIdentity)
		rel, err := a.AddAttributedTo(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(a.ID, rel.Source)
		assert.Equal(RelationshipTypeAttrubutedTo, rel.RelationshipType)
	})

	t.Run("invalid_type", func(t *testing.T) {
		a, err := NewThreatActor(name)
		assert.NoError(err)
		id := NewIdentifier(TypeIPv4Addr)
		rel, err := a.AddAttributedTo(id)
		assert.Equal(err, ErrInvalidParameter)
		assert.Nil(rel)
	})
}

func TestThreatActorCompromises(t *testing.T) {
	assert := assert.New(t)
	name := "ThreatActor name"

	t.Run("Infrastructure", func(t *testing.T) {
		a, err := NewThreatActor(name)
		assert.NoError(err)
		id := NewIdentifier(TypeInfrastructure)
		rel, err := a.AddCompromises(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(a.ID, rel.Source)
		assert.Equal(RelationshipTypeCompromises, rel.RelationshipType)
	})

	t.Run("invalid_type", func(t *testing.T) {
		a, err := NewThreatActor(name)
		assert.NoError(err)
		id := NewIdentifier(TypeIPv4Addr)
		rel, err := a.AddCompromises(id)
		assert.Equal(err, ErrInvalidParameter)
		assert.Nil(rel)
	})
}

func TestThreatActorHosts(t *testing.T) {
	assert := assert.New(t)
	name := "ThreatActor name"

	t.Run("Infrastructure", func(t *testing.T) {
		a, err := NewThreatActor(name)
		assert.NoError(err)
		id := NewIdentifier(TypeInfrastructure)
		rel, err := a.AddHosts(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(a.ID, rel.Source)
		assert.Equal(RelationshipTypeHosts, rel.RelationshipType)
	})

	t.Run("invalid_type", func(t *testing.T) {
		a, err := NewThreatActor(name)
		assert.NoError(err)
		id := NewIdentifier(TypeIPv4Addr)
		rel, err := a.AddHosts(id)
		assert.Equal(err, ErrInvalidParameter)
		assert.Nil(rel)
	})
}

func TestThreatActorOwns(t *testing.T) {
	assert := assert.New(t)
	name := "ThreatActor name"

	t.Run("Infrastructure", func(t *testing.T) {
		a, err := NewThreatActor(name)
		assert.NoError(err)
		id := NewIdentifier(TypeInfrastructure)
		rel, err := a.AddOwns(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(a.ID, rel.Source)
		assert.Equal(RelationshipTypeOwns, rel.RelationshipType)
	})

	t.Run("invalid_type", func(t *testing.T) {
		a, err := NewThreatActor(name)
		assert.NoError(err)
		id := NewIdentifier(TypeIPv4Addr)
		rel, err := a.AddOwns(id)
		assert.Equal(err, ErrInvalidParameter)
		assert.Nil(rel)
	})
}

func TestThreatActorImpersonates(t *testing.T) {
	assert := assert.New(t)
	name := "ThreatActor name"

	t.Run("identity", func(t *testing.T) {
		a, err := NewThreatActor(name)
		assert.NoError(err)
		id := NewIdentifier(TypeIdentity)
		rel, err := a.AddImpersonates(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(a.ID, rel.Source)
		assert.Equal(RelationshipTypeImpersonates, rel.RelationshipType)
	})

	t.Run("invalid_type", func(t *testing.T) {
		a, err := NewThreatActor(name)
		assert.NoError(err)
		id := NewIdentifier(TypeIPv4Addr)
		rel, err := a.AddImpersonates(id)
		assert.Equal(err, ErrInvalidParameter)
		assert.Nil(rel)
	})
}

func TestThreatActorLocatedAt(t *testing.T) {
	assert := assert.New(t)
	name := "ThreatActor name"

	t.Run("location", func(t *testing.T) {
		a, err := NewThreatActor(name)
		assert.NoError(err)
		id := NewIdentifier(TypeLocation)
		rel, err := a.AddLocatedAt(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(a.ID, rel.Source)
		assert.Equal(RelationshipTypeLocatedAt, rel.RelationshipType)
	})

	t.Run("invalid_type", func(t *testing.T) {
		a, err := NewThreatActor(name)
		assert.NoError(err)
		id := NewIdentifier(TypeIPv4Addr)
		rel, err := a.AddLocatedAt(id)
		assert.Equal(err, ErrInvalidParameter)
		assert.Nil(rel)
	})
}

func TestThreatActorTargets(t *testing.T) {
	assert := assert.New(t)
	name := "ThreatActor name"

	t.Run("identity", func(t *testing.T) {
		a, err := NewThreatActor(name)
		assert.NoError(err)
		id := NewIdentifier(TypeIdentity)
		rel, err := a.AddTargets(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(a.ID, rel.Source)
		assert.Equal(RelationshipTypeTargets, rel.RelationshipType)
	})

	t.Run("location", func(t *testing.T) {
		a, err := NewThreatActor(name)
		assert.NoError(err)
		id := NewIdentifier(TypeLocation)
		rel, err := a.AddTargets(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(a.ID, rel.Source)
		assert.Equal(RelationshipTypeTargets, rel.RelationshipType)
	})

	t.Run("vulnerability", func(t *testing.T) {
		a, err := NewThreatActor(name)
		assert.NoError(err)
		id := NewIdentifier(TypeVulnerability)
		rel, err := a.AddTargets(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(a.ID, rel.Source)
		assert.Equal(RelationshipTypeTargets, rel.RelationshipType)
	})

	t.Run("invalid_type", func(t *testing.T) {
		a, err := NewThreatActor(name)
		assert.NoError(err)
		id := NewIdentifier(TypeIPv4Addr)
		rel, err := a.AddTargets(id)
		assert.Equal(err, ErrInvalidParameter)
		assert.Nil(rel)
	})
}

func TestThreatActorUses(t *testing.T) {
	assert := assert.New(t)
	name := "ThreatActor name"

	t.Run("attack-pattern", func(t *testing.T) {
		a, err := NewThreatActor(name)
		assert.NoError(err)
		id := NewIdentifier(TypeAttackPattern)
		rel, err := a.AddUses(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(a.ID, rel.Source)
		assert.Equal(RelationshipTypeUses, rel.RelationshipType)
	})

	t.Run("Infrastructure", func(t *testing.T) {
		a, err := NewThreatActor(name)
		assert.NoError(err)
		id := NewIdentifier(TypeInfrastructure)
		rel, err := a.AddUses(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(a.ID, rel.Source)
		assert.Equal(RelationshipTypeUses, rel.RelationshipType)
	})

	t.Run("malware", func(t *testing.T) {
		a, err := NewThreatActor(name)
		assert.NoError(err)
		id := NewIdentifier(TypeMalware)
		rel, err := a.AddUses(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(a.ID, rel.Source)
		assert.Equal(RelationshipTypeUses, rel.RelationshipType)
	})

	t.Run("tool", func(t *testing.T) {
		a, err := NewThreatActor(name)
		assert.NoError(err)
		id := NewIdentifier(TypeTool)
		rel, err := a.AddUses(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(a.ID, rel.Source)
		assert.Equal(RelationshipTypeUses, rel.RelationshipType)
	})

	t.Run("invalid_type", func(t *testing.T) {
		a, err := NewThreatActor(name)
		assert.NoError(err)
		id := NewIdentifier(TypeIPv4Addr)
		rel, err := a.AddUses(id)
		assert.Equal(err, ErrInvalidParameter)
		assert.Nil(rel)
	})
}
