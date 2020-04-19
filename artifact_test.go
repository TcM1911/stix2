// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestArtifact(t *testing.T) {
	assert := assert.New(t)

	payload := Binary([]byte("Hello World"))
	mime := "mime/type"
	url := "url://"
	hashes := Hashes{"SHA-256": "2cbb138d4097f05fffeb968b34a4e62884fc4755d7d043e2d3760950f1e1a9ee", "MD5": "0da609bd9ec46237557373f1c5cfcae9"}
	key := "key"

	t.Run("missing_property", func(t *testing.T) {
		obj, err := NewArtifact(nil)
		assert.Nil(obj)
		assert.Equal(ErrPropertyMissing, err)
	})

	t.Run("url_and_payload", func(t *testing.T) {
		obj, err := NewArtifact(ArtifactOptionURL(url), ArtifactOptionPayload(payload))
		assert.Nil(obj)
		assert.Equal(err, ErrInvalidParameter)
	})

	t.Run("url_and_no_hash", func(t *testing.T) {
		obj, err := NewArtifact(ArtifactOptionURL(url))
		assert.Nil(obj)
		assert.Equal(err, ErrPropertyMissing)
	})

	t.Run("url_and_hash", func(t *testing.T) {
		obj, err := NewArtifact(ArtifactOptionURL(url), ArtifactOptionHashes(hashes))
		assert.NoError(err)
		assert.Equal(url, obj.URL)
	})

	t.Run("payload_with_options", func(t *testing.T) {
		marking := make([]*GranularMarking, 0)
		objmark := []Identifier{Identifier("id")}
		specVer := "2.0"

		opts := []ArtifactOption{
			ArtifactOptionGranularMarking(marking),
			ArtifactOptionObjectMarking(objmark),
			ArtifactOptionSpecVersion(specVer),
			ArtifactOptionDefanged(true),
			ArtifactOptionExtension("test", struct{}{}),
			//
			ArtifactOptionMimeType(mime),
			ArtifactOptionPayload(payload),
			ArtifactOptionHashes(hashes),
			ArtifactOptionEncryption(EncryptionAlgorithmAES256GCM),
			ArtifactOptionKey(key),
		}
		obj, err := NewArtifact(opts...)
		assert.NotNil(obj)
		assert.NoError(err)
		assert.Equal(marking, obj.GranularMarking)
		assert.Equal(objmark, obj.ObjectMarking)
		assert.Equal(specVer, obj.SpecVersion)
		assert.True(obj.Defanged)

		assert.Equal(mime, obj.MimeType)
		assert.Equal(payload, obj.Payload)
		assert.Equal(hashes, obj.Hashes)
		assert.Equal(EncryptionAlgorithmAES256GCM, obj.Encryption)
		assert.Equal(key, obj.Key)
	})

	t.Run("id-generation", func(t *testing.T) {
		tests := []struct {
			payload Binary
			hashes  Hashes
			id      string
		}{
			{payload, nil, "artifact--2640de4e-9baf-5a92-8f14-dcc7628ec983"},
			{payload, hashes, "artifact--ead91fe9-8a76-5413-9feb-94292e1622ea"},
			{nil, hashes, "artifact--e9ad4fc1-2f44-538d-98c5-5e226ea95501"},
		}
		for _, test := range tests {
			var arg ArtifactOption
			if test.payload == nil {
				arg = ArtifactOptionURL(url)
			} else {
				arg = ArtifactOptionPayload(test.payload)
			}
			obj, err := NewArtifact(
				arg,
				ArtifactOptionHashes(test.hashes),
			)
			assert.NoError(err)
			assert.Equal(Identifier(test.id), obj.ID)
		}
	})

	t.Run("parse_json", func(t *testing.T) {
		data := []byte(`{
  "type": "artifact",
  "spec_version": "2.1",
  "id": "artifact--6f437177-6e48-5cf8-9d9e-872a2bddd641",
  "mime_type": "application/zip",
  "payload_bin": "SGVsbG8gV29ybGQ=",
  "encryption_algorithm": "mime-type-indicated",
  "decryption_key": "My voice is my passport"
}`)
		var obj *Artifact
		err := json.Unmarshal(data, &obj)
		assert.NoError(err)
		assert.Equal(Identifier("artifact--6f437177-6e48-5cf8-9d9e-872a2bddd641"), obj.ID)
		assert.Equal("2.1", obj.SpecVersion)
		assert.Equal(TypeArtifact, obj.Type)
		assert.Equal("application/zip", obj.MimeType)
		assert.Equal("SGVsbG8gV29ybGQ=", obj.Payload.String())
		assert.Equal(EncryptionAlgorithmMimeTypeIndicated, obj.Encryption)
		assert.Equal("My voice is my passport", obj.Key)
	})
}

func TestEncryptionAlgorithm(t *testing.T) {
	assert := assert.New(t)

	t.Run("stringer", func(t *testing.T) {
		tests := []struct {
			expected string
			alg      EncryptionAlgorithm
		}{
			{"AES-256-GCM", EncryptionAlgorithmAES256GCM},
			{"ChaCha20-Poly1305", EncryptionAlgorithmChaCha20Poly1305},
			{"mime-type-indicated", EncryptionAlgorithmMimeTypeIndicated},
		}

		for _, test := range tests {
			assert.Equal(test.expected, test.alg.String())
		}
	})

	t.Run("unmarshalJSON", func(t *testing.T) {
		data := []byte(`{
  "type": "artifact",
  "spec_version": "2.1",
  "encryption_algorithm": "something not accepted"
}`)
		var obj *Artifact
		err := json.Unmarshal(data, &obj)
		assert.NoError(err)
		assert.Equal(EncryptionAlgorithmNone, obj.Encryption)
	})
}
