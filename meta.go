// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import (
	"encoding/json"
	"time"
)

// LanguageContent represents text content for STIX Objects represented in
// languages other than that of the original object. Language content may be a
// translation of the original object by a third-party, a first-source
// translation by the original publisher, or additional official language
// content provided at the time of creation.
type LanguageContent struct {
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
	CreatedBy Identifier `json:"created_by_ref,omitempty"`
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
	// The confidence property identifies the confidence that the creator has
	// in the correctness of their data. The confidence value MUST be a number
	// in the range of 0-100.
	Confidence int `json:"confidence,omitempty"`
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
	// Specifies any extensions of the object, as a dictionary.
	Extensions Extensions `json:"extensions,omitempty"`
	// Object identifies the id of the object that this Language Content
	// applies to. It MUST be the identifier for a STIX Object.
	Object Identifier `json:"object_ref"`
	// ObjectModified identifies the modified time of the object that this
	// Language Content applies to. It MUST be an exact match for the modified
	// time of the STIX Object being referenced.
	ObjectModified *Timestamp `json:"object_modified,omitempty"`
	// Contents contains the actual Language Content (translation).
	//
	// The keys in the dictionary MUST be RFC 5646 language codes for which
	// language content is being provided [RFC5646]. The values each consist of
	// a dictionary that mirrors the properties in the target object
	// (identified by object_ref and object_modified). For example, to provide
	// a translation of the name property on the target object the key in the
	// dictionary would be name.
	// For each key in the nested dictionary:
	//	* If the original property is a string, the corresponding property
	//	in the language content object MUST contain a string with the
	//	content for that property in the language of the top-level key.
	//	* If the original property is a list, the corresponding property in
	//	the translation object must also be a list. Each item in this list
	//	recursively maps to the item at the same position in the list
	//	contained in the target object. The lists MUST have the same
	//	length.
	//	* In the event that translations are only provided for some list
	//	items, the untranslated list items MUST be represented by an empty
	//	string (""). This indicates to a consumer of the Language Content
	//	object that they should interpolate the translated list items in
	//	the Language Content object with the corresponding (untranslated)
	//	list items from the original object as indicated by the object_ref
	//	property.
	//	* If the original property is an object (including dictionaries),
	//	the corresponding location in the translation object must also be
	//	an object. Each key/value field in this object recursively maps to
	//	the object with the same key in the original.
	//
	// The translation object MAY contain only a subset of the translatable
	// fields of the original. Keys that point to non-translatable properties
	// in the target or to properties that do not exist in the target object
	// MUST be ignored.
	Contents map[string]map[string]interface{} `json:"contents"`

	toplevelProperties *CustomObject
}

func (s *LanguageContent) addCustomProperties(c *CustomObject) {
	s.toplevelProperties = c
}

// GetExtendedTopLevelProperties returns the extra top level properties or
// nil for the object.
func (s *LanguageContent) GetExtendedTopLevelProperties() *CustomObject {
	return s.toplevelProperties
}

// GetID returns the identifier for the object.
func (l *LanguageContent) GetID() Identifier {
	return l.ID
}

// GetType returns the object's type.
func (l *LanguageContent) GetType() STIXType {
	return l.Type
}

// GetCreated returns the created time for the STIX object. If the object
// does not have a time defined, nil is returned.
func (l *LanguageContent) GetCreated() *time.Time {
	if l.Created == nil {
		return nil
	}
	return &l.Created.Time
}

// GetModified returns the modified time for the STIX object. If the object
// does not have a time defined, nil is returned.
func (l *LanguageContent) GetModified() *time.Time {
	if l.Modified == nil {
		return nil
	}
	return &l.Modified.Time
}

// NewLanguageContent creates a new LanguageContent object.
func NewLanguageContent(object Identifier, content map[string]map[string]interface{}, opts ...STIXOption) (*LanguageContent, error) {
	if object == "" || content == nil {
		return nil, ErrPropertyMissing
	}
	id := NewIdentifier(TypeLanguageContent)
	t := &Timestamp{time.Now()}
	obj := &LanguageContent{
		Type:        TypeLanguageContent,
		ID:          id,
		SpecVersion: SpecVersion21,
		Created:     t,
		Modified:    t,
		Object:      object,
		Contents:    content,
	}

	err := applyOptions(obj, opts)
	return obj, err
}

// MarkingDefinition represents a specific marking. Data markings typically
// represent handling or sharing requirements for data and are applied in the
// object_marking_refs and granular_markings properties on STIX Objects, which
// reference a list of IDs for marking-definition objects.
//
// Two marking definition types are defined in this specification: TLP, to
// capture TLP markings, and Statement, to capture text marking statements. In
// addition, it is expected that the FIRST Information Exchange Policy (IEP)
// will be included in a future version once a machine-usable specification for
// it has been defined.
//
// Unlike other STIX Objects, Marking Definition objects cannot be versioned
// because it would allow for indirect changes to the markings on a STIX
// Object. For example, if a Statement marking is changed from "Reuse Allowed"
// to "Reuse Prohibited", all STIX Objects marked with that Statement marking
// would effectively have an updated marking without being updated themselves.
// Instead, a new Statement marking with the new text should be created and the
// marked objects updated to point to the new marking.
type MarkingDefinition struct {
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
	CreatedBy Identifier `json:"created_by_ref,omitempty"`
	// The created property represents the time at which the object was
	// originally created. The object creator can use the time it deems most
	// appropriate as the time the object was created, but it MUST be precise
	// to the nearest millisecond (exactly three digits after the decimal place
	// in seconds). The created property MUST NOT be changed when creating a
	// new version of the object.
	Created *Timestamp `json:"created"`
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
	// Specifies any extensions of the object, as a dictionary.
	Extensions Extensions `json:"extensions,omitempty"`
	// Name is used to identify the Marking Definition.
	Name string `json:"name,omitempty"`
	// DefinitionType identifies the type of Marking Definition. The value of
	// the definition_type property SHOULD be one of statement or tlp.
	DefinitionType string `json:"definition_type"`
	// Definition contains the marking object itself (e.g., the TLP marking,
	// the Statement, or some other marking definition defined).
	Definition interface{} `json:"definition"`

	toplevelProperties *CustomObject
}

func (s *MarkingDefinition) addCustomProperties(c *CustomObject) {
	s.toplevelProperties = c
}

// GetExtendedTopLevelProperties returns the extra top level properties or
// nil for the object.
func (s *MarkingDefinition) GetExtendedTopLevelProperties() *CustomObject {
	return s.toplevelProperties
}

// GetID returns the identifier for the object.
func (m *MarkingDefinition) GetID() Identifier {
	return m.ID
}

// GetType returns the object's type.
func (m *MarkingDefinition) GetType() STIXType {
	return m.Type
}

// GetCreated returns the created time for the STIX object. If the object
// does not have a time defined, nil is returned.
func (m *MarkingDefinition) GetCreated() *time.Time {
	if m.Created == nil {
		return nil
	}
	return &m.Created.Time
}

// GetModified returns the modified time for the STIX object. If the object
// does not have a time defined, nil is returned.
func (m *MarkingDefinition) GetModified() *time.Time {
	return nil
}

// NewMarkingDefinition creates a new MarkingDefinition object.
func NewMarkingDefinition(typ string, definition interface{}, opts ...STIXOption) (*MarkingDefinition, error) {
	if typ == "" || definition == nil {
		return nil, ErrPropertyMissing
	}
	id := NewIdentifier(TypeMarkingDefinition)
	t := &Timestamp{time.Now()}
	obj := &MarkingDefinition{
		Type:           TypeMarkingDefinition,
		ID:             id,
		SpecVersion:    SpecVersion21,
		Created:        t,
		DefinitionType: typ,
		Definition:     definition,
	}

	err := applyOptions(obj, opts)
	return obj, err
}

// GranularMarking defines how the marking-definition object referenced by the
// Marking property or a language specified by the Lang property applies to a
// set of content identified by the list of selectors in the Selectors
// property.
type GranularMarking struct {
	// Lang property identifies the language of the text identified by this
	// marking. The value of the lang property, if present, MUST be an RFC5646
	// language code.
	Lang string `json:"lang,omitempty"`
	// Marking  property specifies the ID of the marking-definition object that
	// describes the marking.
	Marking Identifier `json:"marking_ref,omitempty"`
	// Selectors property specifies a list of selectors for content contained
	// within the STIX Object in which this property appears.
	Selectors []string `json:"selectors"`
}

// StatementMarking type defines the representation of a textual marking
// statement (e.g., copyright, terms of use, etc.) in a definition. The value
// of the DefinitionType property MUST be statement when using this marking
// type. Statement markings are generally not machine-readable, and this
// specification does not define any behavior or actions based on their values.
type StatementMarking struct {
	// Statement  (e.g., copyright, terms of use) applied to the content marked
	// by this marking definition.
	Statement string `json:"statement"`
}

// TLPMarking marking type defines how you would represent a Traffic Light
// Protocol (TLP) marking in a definition property. The value of the
// DefinitionType property MUST be tlp when using this marking type.
type TLPMarking struct {
	// TLP level of the content marked by this marking definition, as defined
	// in this section.
	TLP string `json:"tlp"`
}

// TLPWhite is the TLP:WHITE marking as defined by STIX 2.1.
var TLPWhite = &MarkingDefinition{}

// TLPGreen is the TLP:GREEN marking as defined by STIX 2.1.
var TLPGreen = &MarkingDefinition{}

// TLPAmber is the TLP:AMBER marking as defined by STIX 2.1.
var TLPAmber = &MarkingDefinition{}

// TLPRed is the TLP:RED marking as defined by STIX 2.1.
var TLPRed = &MarkingDefinition{}

func init() {
	mustParseTLP(tlpWhiteJSON, TLPWhite)
	mustParseTLP(tlpGreenJSON, TLPGreen)
	mustParseTLP(tlpAmberJSON, TLPAmber)
	mustParseTLP(tlpRedJSON, TLPRed)
}

func mustParseTLP(data []byte, def *MarkingDefinition) {
	err := json.Unmarshal(data, &def)
	if err != nil {
		panic("Failed to parse TLP data: " + err.Error())
	}
}

var tlpWhiteJSON = []byte(
	`
{
  "type": "marking-definition",
  "spec_version": "2.1",
  "id": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
  "created": "2017-01-20T00:00:00.000Z",
  "definition_type": "tlp",
  "name": "TLP:WHITE",
  "definition": {
    "tlp": "white"
  }
}
`)
var tlpGreenJSON = []byte(
	`
{
  "type": "marking-definition",
  "spec_version": "2.1",
  "id": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
  "created": "2017-01-20T00:00:00.000Z",
  "definition_type": "tlp",
  "name": "TLP:GREEN",
  "definition": {
    "tlp": "green"
  }
}
`)
var tlpAmberJSON = []byte(
	`
{
  "type": "marking-definition",
  "spec_version": "2.1",
  "id": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
  "created": "2017-01-20T00:00:00.000Z",
  "definition_type": "tlp",
  "name": "TLP:AMBER",
  "definition": {
    "tlp": "amber"
  }
}
`)
var tlpRedJSON = []byte(
	`
{
  "type": "marking-definition",
  "spec_version": "2.1",
  "id": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
  "created": "2017-01-20T00:00:00.000Z",
  "definition_type": "tlp",
  "name": "TLP:RED",
  "definition": {
    "tlp": "red"
  }
}
`)
