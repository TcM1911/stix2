// Copyright 2021 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import (
	"encoding/json"
	"time"
)

type Extensions map[string]interface{}

func (o *Extensions) UnmarshalJSON(b []byte) error {
	tmp := map[string]json.RawMessage{}

	err := json.Unmarshal(b, &tmp)
	if err != nil {
		return err
	}

	final := make(map[string]interface{})

	// Parse the extensions.
	for k, v := range tmp {
		var ext interface{}
		switch k {
		case ExtArchive:
			ext = &ArchiveFileExtension{}
		case ExtHTTPRequest:
			ext = &HTTPRequestExtension{}
		case ExtICMP:
			ext = &ICMPExtension{}
		case ExtNTFS:
			ext = &NTFSFileExtension{}
		case ExtPDF:
			ext = &PDFExtension{}
		case ExtRasterImage:
			ext = &RasterImageExtension{}
		case ExtSocket:
			ext = &SocketExtension{}
		case ExtTCP:
			ext = &TCPExtension{}
		case ExtUnixAccount:
			ext = &UNIXAccountExtension{}
		case ExtWindowsPEBinary:
			ext = &WindowsPEBinaryExtension{}
		case ExtWindowsProcess:
			ext = &WindowsProcessExtension{}
		case ExtWindowsService:
			ext = &WindowsServiceExtension{}
		default:
			ext = &CustomObject{}
		}

		err = json.Unmarshal(v, ext)
		if err != nil {
			return err
		}
		final[k] = ext
	}

	// Set the value.
	*o = final
	return nil
}

type ExtensionDefinition struct {
	// The type property identifies the type of STIX Object. The value of the
	// type property MUST be the name of one of the types of STIX Objects
	Type STIXType `json:"type"`
	// The id property uniquely identifies this object. For objects that
	// support versioning, all objects with the same id are considered
	// different versions of the same object and the version of the object is
	// identified by its modified property.
	ID Identifier `json:"id"`
	// The version of the STIX specification used to represent this object.
	SpecVersion string `json:"spec_version"`
	// The created_by_ref property specifies the id property of the identity
	// object that describes the entity that created this object. If this
	// attribute is omitted, the source of this information is undefined. This
	// may be used by object creators who wish to remain anonymous.
	CreatedBy Identifier `json:"created_by_ref"`
	// The created property represents the time at which the object was
	// originally created. The object creator can use the time it deems most
	// appropriate as the time the object was created, but it MUST be precise
	// to the nearest millisecond (exactly three digits after the decimal place
	// in seconds). The created property MUST NOT be changed when creating a
	// new version of the object.
	Created *Timestamp `json:"created"`
	// The modified property is only used by STIX Objects that support
	// versioning and represents the time that this particular version of the
	// object was last modified. The object creator can use the time it deems
	// most appropriate as the time this version of the object was modified,
	// but it must be precise to the nearest millisecond (exactly three digits
	// after the decimal place in seconds). If the created property is defined,
	// then the value of the modified property for a given object version MUST
	// be later than or equal to the value of the created property. Object
	// creators MUST set the modified property when creating a new version of
	// an object if the created property was set.
	Modified *Timestamp `json:"modified"`
	// The revoked property is only used by STIX Objects that support
	// versioning and indicates whether the object has been revoked. Revoked
	// objects are no longer considered valid by the object creator. Revoking
	// an object is permanent; future versions of the object with this id MUST
	// NOT be created.
	Revoked bool `json:"revoked,omitempty"`
	// The labels property specifies a set of terms used to describe this
	// object. The terms are user-defined or trust-group defined and their
	// meaning is outside the scope of this specification and MAY be ignored.
	// Where an object has a specific property defined in the specification for
	// characterizing subtypes of that object, the labels property MUST NOT be
	// used for that purpose. For example, the Malware SDO has a property
	// malware_types that contains a list of Malware subtypes (dropper, RAT,
	// etc.). In this example, the labels property cannot be used to describe
	// these Malware subtypes.
	Labels []string `json:"labels,omitempty"`
	// The ExternalReferences property specifies a list of external references
	// which refers to non-STIX information. This property is used to provide
	// one or more URLs, descriptions, or IDs to records in other systems.
	ExternalReferences []*ExternalReference `json:"external_references,omitempty"`
	// The object_marking_refs property specifies a list of id properties of
	// marking-definition objects that apply to this object. In some cases,
	// though uncommon, marking definitions themselves may be marked with
	// sharing or handling guidance. In this case, this property MUST NOT
	// contain any references to the same Marking Definition object (i.e., it
	// cannot contain any circular references).
	ObjectMarking []Identifier `json:"object_marking_refs,omitempty"`
	// The granular_markings property specifies a list of granular markings
	// applied to this object. In some cases, though uncommon, marking
	// definitions themselves may be marked with sharing or handling guidance.
	// In this case, this property MUST NOT contain any references to the same
	// Marking Definition object (i.e., it cannot contain any circular
	// references).
	GranularMarking []*GranularMarking `json:"granular_markings,omitempty"`
	// Name used for display purposes during execution, development, or debugging.
	Name string `json:"name"`
	// Description is a detailed explanation of what data the extension conveys and
	// how it is intended to be used.
	// While the description property is optional this property SHOULD be populated.
	// Note that the schema property is the normative definition of the extension,
	// and this property, if present, is for documentation purposes only.
	Description string `json:"description,omitempty"`
	// Schema is the normative definition of the extension, either as a URL or as
	// plain text explaining the definition.
	// A URL SHOULD point to a JSON schema or a location that contains information
	// about the schema.
	// NOTE: It is recommended that an external reference be provided to the
	// comprehensive documentation of the extension-definition.
	Schema string `json:"schema"`
	// Version of this extension. Producers of STIX extensions are encouraged to
	// follow standard semantic versioning procedures where the version number
	// follows the pattern, MAJOR.MINOR.PATCH. This will allow consumers to
	// distinguish between the three different levels of compatibility typically
	// identified by such versioning strings.
	Version string `json:"version"`
	// ExtensionTypes property specifies one or more extension types contained
	// within this extension.
	// When this property includes toplevel-property- extension then the
	// extension_properties property SHOULD include one or more property names.
	ExtensionTypes []ExtensionType `json:"extension_types"`
	// ExtensionProperties contains the list of new property names that are added
	// to an object by an extension.
	// This property MUST only be used when the extension_types property includes
	// a value of toplevel- property-extension. In other words, when new properties
	// are being added at the top-level of an existing object.
	ExtensionProperties []string `json:"extension_properties,omitempty"`
}

// NewExtensionDefinition creates a new ExtensionDefinition object.
func NewExtensionDefinition(name string, schema string, version string, extTypes []ExtensionType, opts ...STIXOption) (*ExtensionDefinition, error) {
	// Check the arguments
	if name == "" ||
		schema == "" ||
		version == "" ||
		len(extTypes) == 0 {
		return nil, ErrInvalidParameter
	}

	now := &Timestamp{time.Now()}
	id := NewIdentifier(TypeExtensionDefinition)
	obj := &ExtensionDefinition{
		Type:           TypeExtensionDefinition,
		ID:             id,
		SpecVersion:    SpecVersion21,
		Created:        now,
		Modified:       now,
		Name:           name,
		Schema:         schema,
		Version:        version,
		ExtensionTypes: extTypes,
	}

	err := applyOptions(obj, opts)
	return obj, err
}

// GetID returns the identifier for the object.
func (e *ExtensionDefinition) GetID() Identifier {
	return e.ID
}

// GetType returns the object's type.
func (e *ExtensionDefinition) GetType() STIXType {
	return e.Type
}

// GetCreated returns the created time for the STIX object. If the object
// does not have a time defined, nil is returned.
func (e *ExtensionDefinition) GetCreated() *time.Time {
	return &e.Created.Time
}

// GetModified returns the modified time for the STIX object. If the object
// does not have a time defined, nil is returned.
func (e *ExtensionDefinition) GetModified() *time.Time {
	return &e.Modified.Time
}

// GetExtendedTopLevelProperties returns the extra top level properties or
// nil for the object.
func (s *ExtensionDefinition) GetExtendedTopLevelProperties() *CustomObject {
	return nil
}

// ExtensionType describes what type of extension it is.
type ExtensionType uint8

// String returns the string representation of the type.
func (typ ExtensionType) String() string {
	return encExtTypeMap[typ]
}

// UnmarshalJSON extracts the encryption algorithm from the json data.
func (typ *ExtensionType) UnmarshalJSON(b []byte) error {
	var s string
	err := json.Unmarshal(b, &s)
	if err != nil {
		return err
	}

	for k, v := range encExtTypeMap {
		if v == s {
			*typ = k
			return nil
		}
	}

	*typ = ExtensionTypeInvalid
	return nil
}

const (
	// ExtensionTypeInvalid indicates that the extension type used is invalid.
	ExtensionTypeInvalid ExtensionType = iota
	// ExtensionTypeNewSDO specifies that the Extension includes a new SDO.
	ExtensionTypeNewSDO
	// ExtensionTypeNewSCO specifies that the Extension includes a new SCO.
	ExtensionTypeNewSCO
	// ExtensionTypeNewSRO specifies that the Extension includes a new SDO.
	ExtensionTypeNewSRO
	// ExtensionTypePropertyExtension specifies that the extension includes
	// additional properties for a given STIX object.
	ExtensionTypePropertyExtension
	// ExtensionTypeToplevelPropertyExtension specifies that the Extension includes
	// additional properties for a given STIX Object at the top-level.
	// Organizations are encouraged to use the property-extension instead of
	// this extension type.
	ExtensionTypeToplevelPropertyExtension
)

var encExtTypeMap = map[ExtensionType]string{
	ExtensionTypeInvalid:                   "",
	ExtensionTypeNewSDO:                    "new-sdo",
	ExtensionTypeNewSCO:                    "new-sco",
	ExtensionTypeNewSRO:                    "new-sro",
	ExtensionTypePropertyExtension:         "property-extension",
	ExtensionTypeToplevelPropertyExtension: "toplevel-property-extension",
}

// CustomObject is a custom STIX object that allows for extending the specification
// by creating a new type.
type CustomObject map[string]interface{}

// Get retrives an attribute from the custom object.
func (c CustomObject) Get(key string) interface{} {
	val, ok := c[key]
	if !ok {
		return nil
	}
	return val
}

// Set adds an attribute to the custom object.
func (c CustomObject) Set(key string, val interface{}) {
	c[key] = val
}

// GetAsString returns the requested attribute as a string.
func (c CustomObject) GetAsString(key string) string {
	s := c.Get(key)
	if s == nil {
		return ""
	}
	return s.(string)
}

// GetAsStringSlice returns the requested attribute as a string slice.
func (c CustomObject) GetAsStringSlice(key string) []string {
	s := c.Get(key)
	if s == nil {
		return nil
	}
	return s.([]string)
}

// GetAsNumber returns the requested attribute as a number.
// The value has to be an expected integer.
func (c CustomObject) GetAsNumber(key string) int64 {
	s := c.Get(key)
	if s == nil {
		return int64(0)
	}

	if i, ok := s.(int64); ok {
		return i
	}

	// The JSON unmarshal converts JSON numbers to float64
	return int64(s.(float64))
}

// GetID returns the identifier for the object.
func (c CustomObject) GetID() Identifier {
	val, ok := c["id"]
	if !ok {
		return Identifier("")
	}
	return Identifier(val.(string))
}

// GetType returns the object's type.
func (c CustomObject) GetType() STIXType {
	val, ok := c["type"]
	if !ok {
		return STIXType("")
	}
	return STIXType(val.(string))
}

// GetCreated returns the created time for the STIX object. If the object
// does not have a time defined, nil is returned.
func (c CustomObject) GetCreated() *time.Time {
	return convTimeString(c, "created")
}

// GetModified returns the modified time for the STIX object. If the object
// does not have a time defined, nil is returned.
func (c CustomObject) GetModified() *time.Time {
	return convTimeString(c, "modified")
}

func convTimeString(c CustomObject, key string) *time.Time {
	ts, ok := c[key]
	if !ok {
		return nil
	}
	t, err := time.Parse(time.RFC3339Nano, ts.(string))
	if err != nil {
		return nil
	}
	return &t
}

// GetExtendedTopLevelProperties returns the extra top level properties or
// nil for the object.
func (s *CustomObject) GetExtendedTopLevelProperties() *CustomObject {
	return nil
}
