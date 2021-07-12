// Copyright 2020 Joakim Kennedy. All rights reserved. Use of this source code
// is governed by the included BSD license.

package stix2

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestEmailAddress(t *testing.T) {
	assert := assert.New(t)

	val := "john@example.com"
	name := "John Doe"
	belong := Identifier("some")

	t.Run("missing_property", func(t *testing.T) {
		obj, err := NewEmailAddress("")
		assert.Nil(obj)
		assert.Equal(ErrInvalidParameter, err)
	})

	t.Run("with_property", func(t *testing.T) {
		obj, err := NewEmailAddress(val, nil)
		assert.NotNil(obj)
		assert.NoError(err)
	})

	t.Run("payload_with_options", func(t *testing.T) {
		marking := make([]*GranularMarking, 0)
		objmark := []Identifier{Identifier("id")}
		specVer := "2.0"

		opts := []STIXOption{
			OptionGranularMarking(marking),
			OptionObjectMarking(objmark),
			OptionSpecVersion(specVer),
			OptionDefanged(true),
			// OptionExtension("test", struct{}{}),
			//
			OptionDisplayName(name),
			OptionBelongsTo(belong),
		}
		obj, err := NewEmailAddress(val, opts...)
		assert.NotNil(obj)
		assert.NoError(err)
		assert.Equal(marking, obj.GranularMarking)
		assert.Equal(objmark, obj.ObjectMarking)
		assert.Equal(specVer, obj.SpecVersion)
		assert.True(obj.Defanged)

		assert.Equal(val, obj.Value)
		assert.Equal(name, obj.DisplayName)
		assert.Equal(belong, obj.BelongsTo)
	})

	t.Run("id-generation", func(t *testing.T) {
		tests := []struct {
			value string
			id    string
		}{
			{"john@example.com", "email-addr--bb25a0d1-62dc-5b80-8e8b-adc7867b2c0e"},
		}
		for _, test := range tests {
			obj, err := NewEmailAddress(test.value)
			assert.NoError(err)
			assert.Equal(Identifier(test.id), obj.ID)
		}
	})

	t.Run("parse_json", func(t *testing.T) {
		data := []byte(`{
  "type": "email-addr",
  "spec_version": "2.1",
  "id": "email-addr--2d77a846-6264-5d51-b586-e43822ea1ea3",
  "value": "john@example.com",
  "display_name": "John Doe"
}`)
		var obj *EmailAddress
		err := json.Unmarshal(data, &obj)
		assert.NoError(err)
		assert.Equal(Identifier("email-addr--2d77a846-6264-5d51-b586-e43822ea1ea3"), obj.ID)
		assert.Equal("2.1", obj.SpecVersion)
		assert.Equal(TypeEmailAddress, obj.Type)
		assert.Equal("john@example.com", obj.Value)
		assert.Equal("John Doe", obj.DisplayName)
	})
}

func TestEmailMessage(t *testing.T) {
	assert := assert.New(t)

	msg := "Email message"
	ts := &Timestamp{time.Now()}
	ref := Identifier("ref")
	headers := map[string][]string{"1": {"2"}}
	multi := []EmailMIME{{ContentType: "type"}}

	t.Run("with_property", func(t *testing.T) {
		obj, err := NewEmailMessage(false, nil)
		assert.NotNil(obj)
		assert.NoError(err)
	})

	t.Run("payload_with_options", func(t *testing.T) {
		marking := make([]*GranularMarking, 0)
		objmark := []Identifier{Identifier("id")}
		specVer := "2.0"

		opts := []STIXOption{
			OptionGranularMarking(marking),
			OptionObjectMarking(objmark),
			OptionSpecVersion(specVer),
			OptionDefanged(true),
			//
			OptionDate(ts),
			OptionContentType(msg),
			OptionFrom(ref),
			OptionSender(ref),
			OptionBCC([]Identifier{ref}),
			OptionCC([]Identifier{ref}),
			OptionTo([]Identifier{ref}),
			OptionMessageID(msg),
			OptionSubject(msg),
			OptionReceivedLines([]string{msg}),
			OptionAdditionalHeaderFields(headers),
			OptionBody(msg),
			OptionBodyMultipart(multi),
			OptionRawEmail(ref),
		}
		obj, err := NewEmailMessage(false, opts...)
		assert.NotNil(obj)
		assert.NoError(err)
		assert.Equal(marking, obj.GranularMarking)
		assert.Equal(objmark, obj.ObjectMarking)
		assert.Equal(specVer, obj.SpecVersion)
		assert.True(obj.Defanged)

		assert.Equal(ts, obj.Date)
		assert.Equal(msg, obj.ContentType)
		assert.Equal(ref, obj.From)
		assert.Equal(ref, obj.Sender)
		assert.Equal([]Identifier{ref}, obj.To)
		assert.Equal([]Identifier{ref}, obj.CC)
		assert.Equal([]Identifier{ref}, obj.BCC)
		assert.Equal(msg, obj.MessageID)
		assert.Equal(msg, obj.Subject)
		assert.Equal([]string{msg}, obj.ReceivedLines)
		assert.Equal(headers, obj.AdditionalHeaderFields)
		assert.Equal(msg, obj.Body)
		assert.Equal(multi, obj.BodyMultipart)
		assert.Equal(ref, obj.RawEmail)
	})

	t.Run("id-generation", func(t *testing.T) {
		tests := []struct {
			from    string
			subject string
			body    string
			id      string
		}{
			{
				"email-addr--bb25a0d1-62dc-5b80-8e8b-adc7867b2c0e",
				"Email subject",
				"email body",
				"email-message--a9bd5119-6529-5269-82e3-42e74ba8d35b",
			},
			{
				"",
				"Email subject",
				"email body",
				"email-message--585c9070-c0c4-54ad-82d0-77516bc0581f",
			},
			{
				"",
				"",
				"email body",
				"email-message--ee3480c0-689f-59d0-b044-333119b86190",
			},
			{
				"",
				"Email subject",
				"",
				"email-message--af1cb084-05fe-5cfc-a2c8-88248b66eb4d",
			},
			{
				"email-addr--bb25a0d1-62dc-5b80-8e8b-adc7867b2c0e",
				"",
				"",
				"email-message--7736448c-44b5-5eb1-bca6-f8655f8260d7",
			},
		}
		for _, test := range tests {
			obj, err := NewEmailMessage(
				false,
				OptionFrom(Identifier(test.from)),
				OptionSubject(test.subject),
				OptionBody(test.body),
			)
			assert.NoError(err)
			assert.Equal(Identifier(test.id), obj.ID)
		}
	})

	t.Run("parse_json_simple", func(t *testing.T) {
		data := []byte(`{
  "type": "email-message",
  "spec_version": "2.1",
  "id": "email-message--72b7698f-10c2-565a-a2a6-b4996a2f2265",
  "from_ref": "email-addr--89f52ea8-d6ef-51e9-8fce-6a29236436ed",
  "to_refs": ["email-addr--e4ee5301-b52d-59cd-a8fa-8036738c7194"],
  "is_multipart": false,
  "date": "1997-11-21T15:55:06.000Z",
  "subject": "Saying Hello"
}`)
		var obj *EmailMessage
		err := json.Unmarshal(data, &obj)
		assert.NoError(err)
		assert.Equal(Identifier("email-message--72b7698f-10c2-565a-a2a6-b4996a2f2265"), obj.ID)
		assert.Equal("2.1", obj.SpecVersion)
		assert.Equal(TypeEmailMessage, obj.Type)
		assert.Equal("Saying Hello", obj.Subject)
		assert.Equal(Identifier("email-addr--89f52ea8-d6ef-51e9-8fce-6a29236436ed"), obj.From)
		assert.False(obj.IsMultipart)
	})
}
