// Copyright 2020 Joakim Kennedy. All rights reserved. Use of this source code
// is governed by the included BSD license.

package stix2

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestInfrastructure(t *testing.T) {
	assert := assert.New(t)

	name := "new name"
	// ts := &Timestamp{time.Now()}
	typ := []string{InfrastructureTypeCommandAndControl}

	t.Run("missing_property", func(t *testing.T) {
		obj, err := NewInfrastructure("", []string{})
		assert.Nil(obj)
		assert.Equal(ErrPropertyMissing, err)
	})

	t.Run("no_optional", func(t *testing.T) {
		obj, err := NewInfrastructure(name, typ, nil)
		assert.NotNil(obj)
		assert.NoError(err)
	})

	t.Run("with_options", func(t *testing.T) {
		conf := 50
		desc := "My description"
		ts := &Timestamp{time.Now()}
		createdBy := NewIdentifier(TypeInfrastructure)
		ref := &ExternalReference{}
		marking := &GranularMarking{}
		lables := []string{"tag1", "tag2"}
		lang := "en"
		objmark := []Identifier{Identifier("id")}
		specVer := "2.0"

		kchain := []*KillChainPhase{&KillChainPhase{}}
		aliases := []string{"1", "2"}

		opts := []InfrastructureOption{
			InfrastructureOptionConfidence(conf),
			InfrastructureOptionCreated(ts),
			InfrastructureOptionModified(ts),
			InfrastructureOptionCreatedBy(createdBy),
			InfrastructureOptionExternalReferences([]*ExternalReference{ref}),
			InfrastructureOptionGranularMarking(marking),
			InfrastructureOptionLables(lables),
			InfrastructureOptionLang(lang),
			InfrastructureOptionObjectMarking(objmark),
			InfrastructureOptionRevoked(true),
			InfrastructureOptionSpecVersion(specVer),
			//
			InfrastructureOptionDesciption(desc),
			InfrastructureOptionKillChainPhase(kchain),
			InfrastructureOptionAliases(aliases),
			InfrastructureOptionFirstSeen(ts),
			InfrastructureOptionLastSeen(ts),
		}
		obj, err := NewInfrastructure(name, typ, opts...)
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
		assert.Equal(kchain, obj.KillChainPhases)
		assert.Equal(ts, obj.FirstSeen)
		assert.Equal(ts, obj.LastSeen)
		assert.Equal(aliases, obj.Aliases)
	})

	t.Run("parse_json", func(t *testing.T) {
		data := []byte(`{
  "type":"infrastructure",
  "spec_version": "2.1",
  "id":"infrastructure--38c47d93-d984-4fd9-b87b-d69d0841628d",
  "created":"2016-05-07T11:22:30.000Z",
  "modified":"2016-05-07T11:22:30.000Z",
  "name":"Poison Ivy C2",
  "infrastructure_types": ["command-and-control"]
}`)
		ts, err := time.Parse(time.RFC3339Nano, "2016-05-07T11:22:30.000Z")
		assert.NoError(err)
		var obj *Infrastructure
		err = json.Unmarshal(data, &obj)
		assert.NoError(err)
		assert.Equal(Identifier("infrastructure--38c47d93-d984-4fd9-b87b-d69d0841628d"), obj.ID)
		assert.Equal("2.1", obj.SpecVersion)
		assert.Equal(TypeInfrastructure, obj.Type)
		assert.Equal("Poison Ivy C2", obj.Name)
		assert.Equal(ts, obj.Created.Time)
		assert.Equal(ts, obj.Modified.Time)
		assert.Contains(obj.InfrastructureTypes, InfrastructureTypeCommandAndControl)
	})
}

func TestInfrastructureCommunicatesWith(t *testing.T) {
	assert := assert.New(t)
	name := "new name"
	typs := []string{InfrastructureTypeCommandAndControl}

	t.Run("infrastructure", func(t *testing.T) {
		obj, err := NewInfrastructure(name, typs)
		assert.NoError(err)
		id := NewIdentifier(TypeInfrastructure)
		rel, err := obj.AddCommunicatesWith(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(obj.ID, rel.Source)
		assert.Equal(RelationshipTypeCommunicatesWith, rel.RelationshipType)
	})

	t.Run("ipv4", func(t *testing.T) {
		obj, err := NewInfrastructure(name, typs)
		assert.NoError(err)
		id := NewIdentifier(TypeIPv4Addr)
		rel, err := obj.AddCommunicatesWith(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(obj.ID, rel.Source)
		assert.Equal(RelationshipTypeCommunicatesWith, rel.RelationshipType)
	})

	t.Run("ipv6", func(t *testing.T) {
		obj, err := NewInfrastructure(name, typs)
		assert.NoError(err)
		id := NewIdentifier(TypeIPv6Addr)
		rel, err := obj.AddCommunicatesWith(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(obj.ID, rel.Source)
		assert.Equal(RelationshipTypeCommunicatesWith, rel.RelationshipType)
	})

	t.Run("domain-name", func(t *testing.T) {
		obj, err := NewInfrastructure(name, typs)
		assert.NoError(err)
		id := NewIdentifier(TypeDomainName)
		rel, err := obj.AddCommunicatesWith(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(obj.ID, rel.Source)
		assert.Equal(RelationshipTypeCommunicatesWith, rel.RelationshipType)
	})

	t.Run("url", func(t *testing.T) {
		obj, err := NewInfrastructure(name, typs)
		assert.NoError(err)
		id := NewIdentifier(TypeURL)
		rel, err := obj.AddCommunicatesWith(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(obj.ID, rel.Source)
		assert.Equal(RelationshipTypeCommunicatesWith, rel.RelationshipType)
	})

	t.Run("invalid_type", func(t *testing.T) {
		obj, err := NewInfrastructure(name, typs)
		assert.NoError(err)
		id := NewIdentifier(TypeAttackPattern)
		rel, err := obj.AddCommunicatesWith(id)
		assert.Equal(err, ErrInvalidParameter)
		assert.Nil(rel)
	})
}

func TestInfrastructureConsistsOf(t *testing.T) {
	assert := assert.New(t)
	name := "new name"
	typs := []string{InfrastructureTypeCommandAndControl}

	t.Run("infrastructure", func(t *testing.T) {
		obj, err := NewInfrastructure(name, typs)
		assert.NoError(err)
		id := NewIdentifier(TypeInfrastructure)
		rel, err := obj.AddConsistsOf(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(obj.ID, rel.Source)
		assert.Equal(RelationshipTypeConsistsOf, rel.RelationshipType)
	})

	t.Run("observed-data", func(t *testing.T) {
		obj, err := NewInfrastructure(name, typs)
		assert.NoError(err)
		id := NewIdentifier(TypeObservedData)
		rel, err := obj.AddConsistsOf(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(obj.ID, rel.Source)
		assert.Equal(RelationshipTypeConsistsOf, rel.RelationshipType)
	})

	t.Run("invalid_type", func(t *testing.T) {
		obj, err := NewInfrastructure(name, typs)
		assert.NoError(err)
		id := NewIdentifier(TypeAttackPattern)
		rel, err := obj.AddConsistsOf(id)
		assert.Equal(err, ErrInvalidParameter)
		assert.Nil(rel)
	})
}

func TestInfrastructureControls(t *testing.T) {
	assert := assert.New(t)
	name := "new name"
	typs := []string{InfrastructureTypeCommandAndControl}

	t.Run("infrastructure", func(t *testing.T) {
		obj, err := NewInfrastructure(name, typs)
		assert.NoError(err)
		id := NewIdentifier(TypeInfrastructure)
		rel, err := obj.AddControls(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(obj.ID, rel.Source)
		assert.Equal(RelationshipTypeControls, rel.RelationshipType)
	})

	t.Run("malware", func(t *testing.T) {
		obj, err := NewInfrastructure(name, typs)
		assert.NoError(err)
		id := NewIdentifier(TypeMalware)
		rel, err := obj.AddControls(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(obj.ID, rel.Source)
		assert.Equal(RelationshipTypeControls, rel.RelationshipType)
	})

	t.Run("invalid_type", func(t *testing.T) {
		obj, err := NewInfrastructure(name, typs)
		assert.NoError(err)
		id := NewIdentifier(TypeIPv4Addr)
		rel, err := obj.AddControls(id)
		assert.Equal(err, ErrInvalidParameter)
		assert.Nil(rel)
	})
}

func TestInfrastructureDelivers(t *testing.T) {
	assert := assert.New(t)
	name := "new name"
	typs := []string{InfrastructureTypeCommandAndControl}

	t.Run("malware", func(t *testing.T) {
		obj, err := NewInfrastructure(name, typs)
		assert.NoError(err)
		id := NewIdentifier(TypeMalware)
		rel, err := obj.AddDelivers(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(obj.ID, rel.Source)
		assert.Equal(RelationshipTypeDelivers, rel.RelationshipType)
	})

	t.Run("invalid_type", func(t *testing.T) {
		obj, err := NewInfrastructure(name, typs)
		assert.NoError(err)
		id := NewIdentifier(TypeIPv4Addr)
		rel, err := obj.AddDelivers(id)
		assert.Equal(err, ErrInvalidParameter)
		assert.Nil(rel)
	})
}

func TestInfrastructureHas(t *testing.T) {
	assert := assert.New(t)
	name := "new name"
	typs := []string{InfrastructureTypeCommandAndControl}

	t.Run("vulnerability", func(t *testing.T) {
		obj, err := NewInfrastructure(name, typs)
		assert.NoError(err)
		id := NewIdentifier(TypeVulnerability)
		rel, err := obj.AddHas(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(obj.ID, rel.Source)
		assert.Equal(RelationshipTypeHas, rel.RelationshipType)
	})

	t.Run("invalid_type", func(t *testing.T) {
		obj, err := NewInfrastructure(name, typs)
		assert.NoError(err)
		id := NewIdentifier(TypeIPv4Addr)
		rel, err := obj.AddHas(id)
		assert.Equal(err, ErrInvalidParameter)
		assert.Nil(rel)
	})
}

func TestInfrastructureHosts(t *testing.T) {
	assert := assert.New(t)
	name := "new name"
	typs := []string{InfrastructureTypeCommandAndControl}

	t.Run("tool", func(t *testing.T) {
		obj, err := NewInfrastructure(name, typs)
		assert.NoError(err)
		id := NewIdentifier(TypeTool)
		rel, err := obj.AddHosts(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(obj.ID, rel.Source)
		assert.Equal(RelationshipTypeHosts, rel.RelationshipType)
	})

	t.Run("malware", func(t *testing.T) {
		obj, err := NewInfrastructure(name, typs)
		assert.NoError(err)
		id := NewIdentifier(TypeMalware)
		rel, err := obj.AddHosts(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(obj.ID, rel.Source)
		assert.Equal(RelationshipTypeHosts, rel.RelationshipType)
	})

	t.Run("invalid_type", func(t *testing.T) {
		obj, err := NewInfrastructure(name, typs)
		assert.NoError(err)
		id := NewIdentifier(TypeIPv4Addr)
		rel, err := obj.AddHosts(id)
		assert.Equal(err, ErrInvalidParameter)
		assert.Nil(rel)
	})
}

func TestInfrastructureLocatedAt(t *testing.T) {
	assert := assert.New(t)
	name := "new name"
	typs := []string{InfrastructureTypeCommandAndControl}

	t.Run("location", func(t *testing.T) {
		obj, err := NewInfrastructure(name, typs)
		assert.NoError(err)
		id := NewIdentifier(TypeLocation)
		rel, err := obj.AddLocatedAt(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(obj.ID, rel.Source)
		assert.Equal(RelationshipTypeLocatedAt, rel.RelationshipType)
	})

	t.Run("invalid_type", func(t *testing.T) {
		obj, err := NewInfrastructure(name, typs)
		assert.NoError(err)
		id := NewIdentifier(TypeIPv4Addr)
		rel, err := obj.AddLocatedAt(id)
		assert.Equal(err, ErrInvalidParameter)
		assert.Nil(rel)
	})
}

func TestInfrastructureUses(t *testing.T) {
	assert := assert.New(t)
	name := "new name"
	typs := []string{InfrastructureTypeCommandAndControl}

	t.Run("infrastructure", func(t *testing.T) {
		obj, err := NewInfrastructure(name, typs)
		assert.NoError(err)
		id := NewIdentifier(TypeInfrastructure)
		rel, err := obj.AddUses(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(obj.ID, rel.Source)
		assert.Equal(RelationshipTypeUses, rel.RelationshipType)
	})

	t.Run("invalid_type", func(t *testing.T) {
		obj, err := NewInfrastructure(name, typs)
		assert.NoError(err)
		id := NewIdentifier(TypeIPv4Addr)
		rel, err := obj.AddUses(id)
		assert.Equal(err, ErrInvalidParameter)
		assert.Nil(rel)
	})
}
