// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import (
	"encoding/json"
	"strings"
)

// Artifact object permits capturing an array of bytes (8-bits), as a
// base64-encoded string, or linking to a file-like payload. One of payload_bin
// or url MUST be provided. It is incumbent on object creators to ensure that
// the URL is accessible for downstream consumers.
type Artifact struct {
	STIXCyberObservableObject
	// MimeType should, whenever feasible, be one of the values defined in the
	// Template column in the IANA media type registry. Maintaining a
	// comprehensive universal catalog of all extant file types is obviously
	// not possible. When specifying a MIME Type not included in the IANA
	// registry, implementers should use their best judgement so as to
	// facilitate interoperability.
	MimeType string `json:"mime_type,omitempty"`
	// Payload specifies the binary data contained in the artifact. This
	// property MUST NOT be present if url is provided.
	Payload Binary `json:"payload_bin,omitempty"`
	// URL a valid URL that resolves to the unencoded content. This property
	// MUST NOT be present if Payload is provided.
	URL string `json:"url,omitempty"`
	// Hashes are hashes for the contents of the URL or the Payload.
	// This property MUST be present when the url property is present.
	Hashes Hashes `json:"hashes,omitempty"`
	// Encryption is used if the artifact is encrypted, specifies the type of
	// encryption algorithm the binary data is encoded in.
	Encryption EncryptionAlgorithm `json:"encryption_algorithm,omitempty"`
	// Key specifies the decryption key for the encrypted binary data. For
	// example, this may be useful in cases of sharing malware samples, which
	// are often encoded in an encrypted archive.
	Key string `json:"decryption_key,omitempty"`
}

func (o *Artifact) MarshalJSON() ([]byte, error) {
	return marshalToJSONHelper(o)
}

// NewArtifact creates a new Artifact object.
func NewArtifact(opts ...STIXOption) (*Artifact, error) {
	base := newSTIXCyberObservableObject(TypeArtifact)
	obj := &Artifact{
		STIXCyberObservableObject: base,
	}

	err := applyOptions(obj, opts)
	if err != nil {
		return nil, err
	}

	if obj.Payload == nil && obj.URL == "" {
		return nil, ErrPropertyMissing
	}
	if obj.Payload != nil && obj.URL != "" {
		return nil, ErrInvalidParameter
	}
	if obj.URL != "" && obj.Hashes == nil {
		return nil, ErrPropertyMissing
	}

	contriStr := []string{}
	if len(obj.Hashes) != 0 {
		contriStr = append(contriStr, obj.Hashes.getIDContribution())
	}
	if len(obj.Payload) != 0 {
		contriStr = append(contriStr, `"`+obj.Payload.String()+`"`)
	}
	obj.ID = NewObservableIdentifier("["+strings.Join(contriStr, ",")+"]", TypeArtifact)
	return obj, nil
}

// EncryptionAlgorithm is the encryption algorithms used for sharing defanged
// and/or confidential artifacts.
type EncryptionAlgorithm uint8

// String returns the string representation of the type.
func (typ EncryptionAlgorithm) String() string {
	return encAlgMap[typ]
}

// MarshalJSON converts the enum type to the JSON string.
func (typ EncryptionAlgorithm) MarshalJSON() ([]byte, error) {
	return json.Marshal(typ.String())
}

// UnmarshalJSON extracts the encryption algorithm from the json data.
func (typ *EncryptionAlgorithm) UnmarshalJSON(b []byte) error {
	t := string(b[1 : len(b)-1])
	for k, v := range encAlgMap {
		if v == t {
			*typ = k
			return nil
		}
	}
	*typ = EncryptionAlgorithmNone
	return nil
}

const (
	// EncryptionAlgorithmNone no encryption is used.
	EncryptionAlgorithmNone EncryptionAlgorithm = iota
	// EncryptionAlgorithmAES256GCM the AES-256-GCM cipher.
	EncryptionAlgorithmAES256GCM
	// EncryptionAlgorithmChaCha20Poly1305 the ChaCha20-Poly1305 stream
	// cipher.
	EncryptionAlgorithmChaCha20Poly1305
	// EncryptionAlgorithmMimeTypeIndicated mean encryption algorithm is
	// self-defined by the artifact's data. The specified mime-type tells you
	// which format it is, e.g., Word Doc or GPG. This is intended for formats
	// like Zip files and Word files which take a simple password, or GPG
	// armored files that contain the key blob along with the file.
	EncryptionAlgorithmMimeTypeIndicated
)

var encAlgMap = map[EncryptionAlgorithm]string{
	EncryptionAlgorithmNone:              "",
	EncryptionAlgorithmAES256GCM:         "AES-256-GCM",
	EncryptionAlgorithmChaCha20Poly1305:  "ChaCha20-Poly1305",
	EncryptionAlgorithmMimeTypeIndicated: "mime-type-indicated",
}
