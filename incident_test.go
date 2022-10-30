package stix2

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestIncident(t *testing.T) {
	assert := assert.New(t)

	name := "New Incident"

	t.Run("missing_property", func(t *testing.T) {
		obj, err := NewIncident("")
		assert.Nil(obj)
		assert.Equal(ErrPropertyMissing, err)
	})

	t.Run("no_optional", func(t *testing.T) {
		obj, err := NewIncident(name, nil)
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
		}
		obj, err := NewIncident(name, opts...)
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

		assert.Equal(name, obj.Name)
		assert.Equal(desc, obj.Description)
	})

	t.Run("parse_json", func(t *testing.T) {
		data := []byte(`{
  "type": "incident",
  "spec_version": "2.1",
  "id": "incident--023d105b-752e-4e3c-941c-7d3f3cb15e9e",
  "created_by_ref": "incident--f431f809-377b-45e0-aa1c-6a4751cae5ff",
  "created": "2016-04-06T20:03:00.000Z",
  "modified": "2016-04-06T20:03:00.000Z",
  "name": "2016 DNC Hack by APT28"
}`)
		ts, err := time.Parse(time.RFC3339Nano, "2016-04-06T20:03:00.000Z")
		assert.NoError(err)
		var obj *Identity
		err = json.Unmarshal(data, &obj)
		assert.NoError(err)
		assert.Equal(Identifier("incident--023d105b-752e-4e3c-941c-7d3f3cb15e9e"), obj.ID)
		assert.Equal("2.1", obj.SpecVersion)
		assert.Equal(TypeIncident, obj.Type)
		assert.Equal("2016 DNC Hack by APT28", obj.Name)
		assert.Equal(ts, obj.Created.Time)
		assert.Equal(ts, obj.Modified.Time)
	})
}
