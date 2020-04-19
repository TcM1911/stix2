// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import (
	"bytes"
	"encoding/json"
	"time"

	"github.com/ugorji/go/codec"
)

const (
	// SpecVersion20 is the spec_version string for STIX™ 2.0.
	SpecVersion20 = "2.0"
	// SpecVersion21 is the spec_version string for STIX™ 2.1.
	SpecVersion21 = "2.1"
)

func newSTIXRelationshipObject(typ StixType) STIXRelationshipObject {
	id := NewIdentifier(typ)
	t := time.Now()
	return STIXRelationshipObject{
		Type:        typ,
		ID:          id,
		SpecVersion: SpecVersion21,
		Created:     &Timestamp{t},
		Modified:    &Timestamp{t},
	}
}

// STIXRelationshipObject is objects that connect STIX Domain Objects together,
// STIX Cyber-observable Objects together, and connect STIX Domain Objects and
// STIX Cyber-observable Objects together to form a more complete understanding
// of the threat landscape.
type STIXRelationshipObject struct {
	// The type property identifies the type of STIX Object. The value of the
	// type property MUST be the name of one of the types of STIX Objects
	Type StixType `json:"type"`
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
	// The lang property identifies the language of the text content in this
	// object. When present, it MUST be a language code conformant to
	// [RFC5646]. If the property is not present, then the language of the
	// content is en (English). This property SHOULD be present if the object
	// type contains translatable text properties (e.g. name, description).
	Lang string `json:"lang,omitempty"`
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
	GranularMarking *GranularMarking `json:"granular_markings,omitempty"`
}

// GetID returns the identifier for the object.
func (s *STIXRelationshipObject) GetID() Identifier {
	return s.ID
}

// GetType returns the object's type.
func (s *STIXRelationshipObject) GetType() StixType {
	return s.Type
}

// GetCreated returns the created time for the STIX object. If the object
// does not have a time defined, nil is returned.
func (s *STIXRelationshipObject) GetCreated() *time.Time {
	if s.Created == nil {
		return nil
	}
	return &s.Created.Time
}

// GetModified returns the modified time for the STIX object. If the object
// does not have a time defined, nil is returned.
func (s *STIXRelationshipObject) GetModified() *time.Time {
	if s.Modified == nil {
		return nil
	}
	return &s.Modified.Time
}

func newSTIXDomainObject(typ StixType) STIXDomainObject {
	id := NewIdentifier(typ)
	t := time.Now()
	return STIXDomainObject{
		Type:        typ,
		ID:          id,
		SpecVersion: SpecVersion21,
		Created:     &Timestamp{t},
		Modified:    &Timestamp{t},
	}
}

// STIXDomainObject are higher Level Intelligence Objects that represent
// behaviors and constructs that threat analysts would typically create or work
// with while understanding the threat landscape.
type STIXDomainObject struct {
	// The type property identifies the type of STIX Object. The value of the
	// type property MUST be the name of one of the types of STIX Objects
	Type StixType `json:"type"`
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
	// The lang property identifies the language of the text content in this
	// object. When present, it MUST be a language code conformant to
	// [RFC5646]. If the property is not present, then the language of the
	// content is en (English). This property SHOULD be present if the object
	// type contains translatable text properties (e.g. name, description).
	Lang string `json:"lang,omitempty"`
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
	GranularMarking *GranularMarking `json:"granular_markings,omitempty"`
}

// AddDerivedFrom adds a relationship to an object that this object is derived
// from.
func (s *STIXDomainObject) AddDerivedFrom(id Identifier, opts ...RelationshipOption) (*Relationship, error) {
	return NewRelationship(RelationshipTypeDerivedFrom, s.ID, id, opts...)
}

// AddDuplicateOf adds a relationship to an object that this object is a
// duplicate of.
func (s *STIXDomainObject) AddDuplicateOf(id Identifier, opts ...RelationshipOption) (*Relationship, error) {
	return NewRelationship(RelationshipTypeDuplicateOf, s.ID, id, opts...)
}

// AddRelatedTo adds a relationship to an object that this object is related
// to.
func (s *STIXDomainObject) AddRelatedTo(id Identifier, opts ...RelationshipOption) (*Relationship, error) {
	return NewRelationship(RelationshipTypeRelatedTo, s.ID, id, opts...)
}

// GetID returns the identifier for the object.
func (s *STIXDomainObject) GetID() Identifier {
	return s.ID
}

// GetType returns the object's type.
func (s *STIXDomainObject) GetType() StixType {
	return s.Type
}

// GetCreated returns the created time for the STIX object. If the object
// does not have a time defined, nil is returned.
func (s *STIXDomainObject) GetCreated() *time.Time {
	if s.Created == nil {
		return nil
	}
	return &s.Created.Time
}

// GetModified returns the modified time for the STIX object. If the object
// does not have a time defined, nil is returned.
func (s *STIXDomainObject) GetModified() *time.Time {
	if s.Modified == nil {
		return nil
	}
	return &s.Modified.Time
}

// STIXCyberObservableObject represent observed facts about a network or host
// that may be used and related to higher level intelligence to form a more
// complete understanding of the threat landscape.
type STIXCyberObservableObject struct {
	// The type property identifies the type of STIX Object. The value of the
	// type property MUST be the name of one of the types of STIX Objects
	Type StixType `json:"type"`
	// The id property uniquely identifies this object. For objects that
	// support versioning, all objects with the same id are considered
	// different versions of the same object and the version of the object is
	// identified by its modified property.
	ID Identifier `json:"id"`
	// The version of the STIX specification used to represent this object.
	SpecVersion string `json:"spec_version,omitempty"`
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
	GranularMarking *GranularMarking `json:"granular_markings,omitempty"`
	// This property defines whether or not the data contained within the
	// object has been defanged.
	Defanged bool `json:"defanged,omitempty"`
	// Specifies any extensions of the object, as a dictionary.
	Extensions map[string]json.RawMessage `json:"extensions,omitempty"`
}

// AddDerivedFrom adds a relationship to an object that this object is derived
// from.
func (o *STIXCyberObservableObject) AddDerivedFrom(id Identifier, opts ...RelationshipOption) (*Relationship, error) {
	return NewRelationship(RelationshipTypeDerivedFrom, o.ID, id, opts...)
}

// AddDuplicateOf adds a relationship to an object that this object is a
// duplicate of.
func (o *STIXCyberObservableObject) AddDuplicateOf(id Identifier, opts ...RelationshipOption) (*Relationship, error) {
	return NewRelationship(RelationshipTypeDuplicateOf, o.ID, id, opts...)
}

// AddRelatedTo adds a relationship to an object that this object is related
// to.
func (o *STIXCyberObservableObject) AddRelatedTo(id Identifier, opts ...RelationshipOption) (*Relationship, error) {
	return NewRelationship(RelationshipTypeRelatedTo, o.ID, id, opts...)
}

// GetID returns the identifier for the object.
func (o *STIXCyberObservableObject) GetID() Identifier {
	return o.ID
}

// GetType returns the object's type.
func (o *STIXCyberObservableObject) GetType() StixType {
	return o.Type
}

// GetCreated returns the created time for the STIX object. If the object
// does not have a time defined, nil is returned.
func (o *STIXCyberObservableObject) GetCreated() *time.Time {
	return nil
}

// GetModified returns the modified time for the STIX object. If the object
// does not have a time defined, nil is returned.
func (o *STIXCyberObservableObject) GetModified() *time.Time {
	return nil
}

func (o *STIXCyberObservableObject) addExtension(key string, val interface{}) {
	if o.Extensions == nil {
		o.Extensions = make(map[string]json.RawMessage)
	}
	// If error drop the data.
	buf := &bytes.Buffer{}
	c := codec.NewEncoder(buf, &codec.JsonHandle{})
	err := c.Encode(val)
	if err != nil {
		return
	}
	o.Extensions[key] = json.RawMessage(buf.Bytes())
}

func (o *STIXCyberObservableObject) canonicalizeExtensions() string {
	if len(o.Extensions) == 0 {
		return ""
	}
	buf := &bytes.Buffer{}
	c := codec.NewEncoder(buf, &codec.JsonHandle{})
	err := c.Encode(o.Extensions)
	if err != nil {
		return ""
	}
	return buf.String()
}

func newSTIXCyberObservableObject(typ StixType) STIXCyberObservableObject {
	return STIXCyberObservableObject{
		Type:        typ,
		SpecVersion: SpecVersion21,
	}
}
