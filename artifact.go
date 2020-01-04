// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import "strings"

// Artifact object permits capturing an array of bytes (8-bits), as a
// base64-encoded string, or linking to a file-like payload. One of payload_bin
// or url MUST be provided. It is incumbent on object creators to ensure that
// the URL is accessible for downstream consumers.
type Artifact struct {
	*STIXCyberObservableObject
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

// NewArtifact creates a new Artifact object.
func NewArtifact(opts ...ArtifactOption) (*Artifact, error) {
	base := newSTIXCyberObservableObject(TypeArtifact)
	obj := &Artifact{
		STIXCyberObservableObject: base,
	}

	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(obj)
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
	obj.ID = NewObservableIdenfier("["+strings.Join(contriStr, ",")+"]", TypeArtifact)
	return obj, nil
}

// ArtifactOption is an optional parameter when constructing a
// Artifact object.
type ArtifactOption func(a *Artifact)

/*
	Base object options
*/

// ArtifactOptionSpecVersion sets the STIX spec version.
func ArtifactOptionSpecVersion(ver string) ArtifactOption {
	return func(obj *Artifact) {
		obj.SpecVersion = ver
	}
}

// ArtifactOptionObjectMarking sets the object marking attribute.
func ArtifactOptionObjectMarking(om []Identifier) ArtifactOption {
	return func(obj *Artifact) {
		obj.ObjectMarking = om
	}
}

// ArtifactOptionGranularMarking sets the granular marking attribute.
func ArtifactOptionGranularMarking(gm *GranularMarking) ArtifactOption {
	return func(obj *Artifact) {
		obj.GranularMarking = gm
	}
}

// ArtifactOptionDefanged sets the defanged attribute.
func ArtifactOptionDefanged(b bool) ArtifactOption {
	return func(obj *Artifact) {
		obj.Defanged = b
	}
}

// ArtifactOptionExtension adds an extension.
func ArtifactOptionExtension(name string, value interface{}) ArtifactOption {
	return func(obj *Artifact) {
		// Ignoring the error.
		obj.addExtension(name, value)
	}
}

/*
	Artifact object options
*/

// ArtifactOptionMimeType sets the mime type attribute.
func ArtifactOptionMimeType(s string) ArtifactOption {
	return func(obj *Artifact) {
		obj.MimeType = s
	}
}

// ArtifactOptionPayload sets the payload attribute.
func ArtifactOptionPayload(s Binary) ArtifactOption {
	return func(obj *Artifact) {
		obj.Payload = s
	}
}

// ArtifactOptionURL sets the URL attribute.
func ArtifactOptionURL(s string) ArtifactOption {
	return func(obj *Artifact) {
		obj.URL = s
	}
}

// ArtifactOptionHashes sets the hashes attribute.
func ArtifactOptionHashes(s Hashes) ArtifactOption {
	return func(obj *Artifact) {
		obj.Hashes = s
	}
}

// ArtifactOptionEncryption sets the encryption algorithm attribute.
func ArtifactOptionEncryption(s EncryptionAlgorithm) ArtifactOption {
	return func(obj *Artifact) {
		obj.Encryption = s
	}
}

// ArtifactOptionKey sets the decryption key attribute.
func ArtifactOptionKey(s string) ArtifactOption {
	return func(obj *Artifact) {
		obj.Key = s
	}
}

// EncryptionAlgorithm is the encryption algorithms used for sharing defanged
// and/or confidential artifacts.
type EncryptionAlgorithm uint8

// String returns the string representation of the type.
func (typ EncryptionAlgorithm) String() string {
	return encAlgMap[typ]
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
