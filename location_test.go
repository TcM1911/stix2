// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestLocation(t *testing.T) {
	assert := assert.New(t)

	region := RegionNorthernAmerica
	country := "us"
	lat := float64(1)
	long := float64(-15)

	t.Run("missing_property", func(t *testing.T) {
		obj, err := NewLocation("", "", float64(0), float64(0))
		assert.Nil(obj)
		assert.Equal(ErrPropertyMissing, err)
	})

	t.Run("no_optional", func(t *testing.T) {
		obj, err := NewLocation(region, country, lat, long, nil)
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

		name := "new name"
		precision := float64(100.2)
		adminArea := "XX"
		city := "City"
		address := "123 Main street"
		postal := "12346"

		opts := []LocationOption{
			LocationOptionConfidence(conf),
			LocationOptionCreated(ts),
			LocationOptionModified(ts),
			LocationOptionCreatedBy(createdBy),
			LocationOptionExternalReferences([]*ExternalReference{ref}),
			LocationOptionGranularMarking(marking),
			LocationOptionLables(lables),
			LocationOptionLang(lang),
			LocationOptionObjectMarking(objmark),
			LocationOptionRevoked(true),
			LocationOptionSpecVersion(specVer),
			//
			LocationOptionDesciption(desc),
			LocationOptionName(name),
			LocationOptionPrecision(precision),
			LocationOptionAdministrativeArea(adminArea),
			LocationOptionCity(city),
			LocationOptionStreetAddress(address),
			LocationOptionPostalCode(postal),
		}
		obj, err := NewLocation(region, country, lat, long, opts...)
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
		assert.Equal(precision, obj.Precision)
		assert.Equal(adminArea, obj.AdminstrativeArea)
		assert.Equal(city, obj.City)
		assert.Equal(address, obj.StreetAddress)
		assert.Equal(postal, obj.PostalCode)
	})

	t.Run("lat-long-precision-validation", func(t *testing.T) {
		tests := []struct {
			lat       float64
			long      float64
			precision float64
			err       error
		}{
			{float64(0), float64(0), float64(0), nil},
			{float64(10), float64(0), float64(0), ErrInvalidProperty},
			{float64(0), float64(10), float64(0), ErrInvalidProperty},
			{float64(-91), float64(10), float64(0), ErrInvalidProperty},
			{float64(10), float64(-181), float64(0), ErrInvalidProperty},
			{float64(91), float64(10), float64(0), ErrInvalidProperty},
			{float64(10), float64(181), float64(0), ErrInvalidProperty},
			{float64(90), float64(180), float64(0), nil},
			{float64(-90), float64(-180), float64(0), nil},
			{float64(0), float64(180), float64(10.1), ErrInvalidProperty},
			{float64(90), float64(0), float64(10.1), ErrInvalidProperty},
			{float64(0), float64(0), float64(10.1), ErrInvalidProperty},
		}
		for _, test := range tests {
			_, err := NewLocation(region, country, test.lat, test.long, LocationOptionPrecision(test.precision))
			assert.Equal(test.err, err)
		}
	})

	t.Run("parse_json", func(t *testing.T) {
		data := []byte(`{
  "type": "location",
  "spec_version": "2.1",
  "id": "location--a6e9345f-5a15-4c29-8bb3-7dcc5d168d64",
  "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
  "created": "2016-04-06T20:03:00.000Z",
  "modified": "2016-04-06T20:03:00.000Z",
  "latitude": 48.8566,
  "longitude": 2.3522
}`)
		ts, err := time.Parse(time.RFC3339Nano, "2016-04-06T20:03:00.000Z")
		assert.NoError(err)
		var obj *Location
		err = json.Unmarshal(data, &obj)
		assert.NoError(err)
		assert.Equal(Identifier("location--a6e9345f-5a15-4c29-8bb3-7dcc5d168d64"), obj.ID)
		assert.Equal("2.1", obj.SpecVersion)
		assert.Equal(TypeLocation, obj.Type)
		assert.Equal(ts, obj.Created.Time)
		assert.Equal(ts, obj.Modified.Time)
		assert.Equal(float64(48.8566), obj.Latitude)
		assert.Equal(float64(2.3522), obj.Longitude)
	})
}
