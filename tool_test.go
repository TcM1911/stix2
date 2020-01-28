// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestTool(t *testing.T) {
	assert := assert.New(t)

	ts := &Timestamp{time.Now()}
	desc := "Tool content"
	name := "Tool name"
	typs := []string{ToolTypeNetworkCapture}
	alias := []string{"Name 1"}
	kcf := []*KillChainPhase{&KillChainPhase{}}
	toolVersion := "1.0"

	t.Run("missing_property", func(t *testing.T) {
		obj, err := NewTool("", []string{}, nil)
		assert.Nil(obj)
		assert.Equal(ErrPropertyMissing, err)
	})

	t.Run("no_optional", func(t *testing.T) {
		obj, err := NewTool(name, typs, nil)
		assert.NotNil(obj)
		assert.NoError(err)
	})

	t.Run("with_options", func(t *testing.T) {
		conf := 50
		createdBy := NewIdentifier(TypeIdentity)
		ref := &ExternalReference{}
		marking := &GranularMarking{}
		lables := []string{"tag1", "tag2"}
		lang := "en"
		objmark := []Identifier{Identifier("id")}
		specVer := "2.0"

		opts := []ToolOption{
			ToolOptionConfidence(conf),
			ToolOptionCreated(ts),
			ToolOptionModified(ts),
			ToolOptionCreatedBy(createdBy),
			ToolOptionExternalReferences([]*ExternalReference{ref}),
			ToolOptionGranularMarking(marking),
			ToolOptionLables(lables),
			ToolOptionLang(lang),
			ToolOptionObjectMarking(objmark),
			ToolOptionRevoked(true),
			ToolOptionSpecVersion(specVer),
			//
			ToolOptionDescription(desc),
			ToolOptionAliases(alias),
			ToolOptionKillChainPhase(kcf),
			ToolOptionToolVersion(toolVersion),
		}
		obj, err := NewTool(name, typs, opts...)
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
		assert.Equal(name, obj.Name)
		assert.Equal(typs, obj.Types)
		assert.Equal(alias, obj.Aliases)
		assert.Equal(kcf, obj.KillChainPhase)
		assert.Equal(toolVersion, obj.ToolVersion)
	})

	t.Run("parse_json", func(t *testing.T) {
		data := []byte(`{
  "type": "tool",
  "spec_version": "2.1",
  "id": "tool--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
  "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
  "created": "2016-04-06T20:03:48.000Z",
  "modified": "2016-04-06T20:03:48.000Z",
  "tool_types": [ "remote-access"],
  "name": "VNC"
}`)
		ts, err := time.Parse(time.RFC3339Nano, "2016-04-06T20:03:48.000Z")
		assert.NoError(err)
		var obj *Tool
		err = json.Unmarshal(data, &obj)
		assert.NoError(err)
		assert.Equal(Identifier("tool--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"), obj.ID)
		assert.Equal("2.1", obj.SpecVersion)
		assert.Equal(TypeTool, obj.Type)
		assert.Equal(ts, obj.Created.Time)
		assert.Equal(ts, obj.Modified.Time)
		assert.Equal("VNC", obj.Name)
		assert.Contains(obj.Types, ToolTypeRemoteAccess)
	})
}

func TestToolDelivers(t *testing.T) {
	assert := assert.New(t)
	name := "Tool name"
	typs := []string{ToolTypeExploitation}

	t.Run("malware", func(t *testing.T) {
		a, err := NewTool(name, typs)
		assert.NoError(err)
		id := NewIdentifier(TypeMalware)
		rel, err := a.AddDelivers(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(a.ID, rel.Source)
		assert.Equal(RelationshipTypeDelivers, rel.RelationshipType)
	})

	t.Run("invalid_type", func(t *testing.T) {
		a, err := NewTool(name, typs)
		assert.NoError(err)
		id := NewIdentifier(TypeIPv4Addr)
		rel, err := a.AddDelivers(id)
		assert.Equal(err, ErrInvalidParameter)
		assert.Nil(rel)
	})
}

func TestToolDrops(t *testing.T) {
	assert := assert.New(t)
	name := "Tool name"
	typs := []string{ToolTypeDenialOfService}

	t.Run("Infrastructure", func(t *testing.T) {
		a, err := NewTool(name, typs)
		assert.NoError(err)
		id := NewIdentifier(TypeMalware)
		rel, err := a.AddDrops(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(a.ID, rel.Source)
		assert.Equal(RelationshipTypeDrops, rel.RelationshipType)
	})

	t.Run("invalid_type", func(t *testing.T) {
		a, err := NewTool(name, typs)
		assert.NoError(err)
		id := NewIdentifier(TypeIPv4Addr)
		rel, err := a.AddDrops(id)
		assert.Equal(err, ErrInvalidParameter)
		assert.Nil(rel)
	})
}

func TestToolHas(t *testing.T) {
	assert := assert.New(t)
	name := "Tool name"
	typs := []string{ToolTypeNetworkCapture}

	t.Run("Infrastructure", func(t *testing.T) {
		a, err := NewTool(name, typs)
		assert.NoError(err)
		id := NewIdentifier(TypeVulnerability)
		rel, err := a.AddHas(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(a.ID, rel.Source)
		assert.Equal(RelationshipTypeHas, rel.RelationshipType)
	})

	t.Run("invalid_type", func(t *testing.T) {
		a, err := NewTool(name, typs)
		assert.NoError(err)
		id := NewIdentifier(TypeIPv4Addr)
		rel, err := a.AddHas(id)
		assert.Equal(err, ErrInvalidParameter)
		assert.Nil(rel)
	})
}

func TestToolTargets(t *testing.T) {
	assert := assert.New(t)
	name := "Tool name"
	typs := []string{ToolTypeVulnerabilityScanning}

	t.Run("identity", func(t *testing.T) {
		a, err := NewTool(name, typs)
		assert.NoError(err)
		id := NewIdentifier(TypeIdentity)
		rel, err := a.AddTargets(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(a.ID, rel.Source)
		assert.Equal(RelationshipTypeTargets, rel.RelationshipType)
	})

	t.Run("Infrastructure", func(t *testing.T) {
		a, err := NewTool(name, typs)
		assert.NoError(err)
		id := NewIdentifier(TypeInfrastructure)
		rel, err := a.AddTargets(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(a.ID, rel.Source)
		assert.Equal(RelationshipTypeTargets, rel.RelationshipType)
	})

	t.Run("location", func(t *testing.T) {
		a, err := NewTool(name, typs)
		assert.NoError(err)
		id := NewIdentifier(TypeLocation)
		rel, err := a.AddTargets(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(a.ID, rel.Source)
		assert.Equal(RelationshipTypeTargets, rel.RelationshipType)
	})

	t.Run("vulnerability", func(t *testing.T) {
		a, err := NewTool(name, typs)
		assert.NoError(err)
		id := NewIdentifier(TypeVulnerability)
		rel, err := a.AddTargets(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(a.ID, rel.Source)
		assert.Equal(RelationshipTypeTargets, rel.RelationshipType)
	})

	t.Run("invalid_type", func(t *testing.T) {
		a, err := NewTool(name, typs)
		assert.NoError(err)
		id := NewIdentifier(TypeIPv4Addr)
		rel, err := a.AddTargets(id)
		assert.Equal(err, ErrInvalidParameter)
		assert.Nil(rel)
	})
}

func TestToolUses(t *testing.T) {
	assert := assert.New(t)
	name := "Tool name"
	typs := []string{ToolTypeInformationGathering}

	t.Run("Infrastructure", func(t *testing.T) {
		a, err := NewTool(name, typs)
		assert.NoError(err)
		id := NewIdentifier(TypeInfrastructure)
		rel, err := a.AddUses(id)
		assert.NoError(err)
		assert.Equal(id, rel.Target)
		assert.Equal(a.ID, rel.Source)
		assert.Equal(RelationshipTypeUses, rel.RelationshipType)
	})

	t.Run("invalid_type", func(t *testing.T) {
		a, err := NewTool(name, typs)
		assert.NoError(err)
		id := NewIdentifier(TypeIPv4Addr)
		rel, err := a.AddUses(id)
		assert.Equal(err, ErrInvalidParameter)
		assert.Nil(rel)
	})
}
