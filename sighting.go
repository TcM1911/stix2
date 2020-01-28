// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import (
	"fmt"
	"time"
)

// Sighting denotes the belief that something in CTI (e.g., an indicator,
// malware, tool, threat actor, etc.) was seen. Sightings are used to track who
// and what are being targeted, how attacks are carried out, and to track
// trends in attack behavior.
//
// The Sighting relationship object is a special type of SRO; it is a
// relationship that contains extra properties not present on the Generic
// Relationship object. These extra properties are included to represent data
// specific to sighting relationships (e.g., count, representing how many times
// something was seen), but for other purposes a Sighting can be thought of as
// a Relationship with a name of "sighting-of". Sighting is captured as a
// relationship because you cannot have a sighting unless you have something
// that has been sighted. Sighting does not make sense without the relationship
// to what was sighted.
//
// Sighting relationships relate three aspects of the sighting:
//
//		* What was sighted, such as the Indicator, Malware, Campaign, or other
//		  SDO (sighting_of_ref)
//		* Who sighted it and/or where it was sighted, represented as an
//		  Identity (where_sighted_refs) and
//		* What was actually seen on systems and networks, represented as
//		  Observed Data (observed_data_refs)
//
// What was sighted is required; a sighting does not make sense unless you say
// what you saw. Who sighted it, where it was sighted, and what was actually
// seen are optional. In many cases it is not necessary to provide that level
// of detail in order to provide value.
//
// Sightings are used whenever any SDO has been "seen". In some cases, the
// object creator wishes to convey very little information about the sighting;
// the details might be sensitive, but the fact that they saw a malware
// instance or threat actor could still be very useful. In other cases,
// providing the details may be helpful or even necessary; saying exactly which
// of the 1000 IP addresses in an indicator were sighted is helpful when
// tracking which of those IPs is still malicious.
type Sighting struct {
	STIXRelationshipObject
	// Description that provides more details and context about the Sighting.
	Description string `json:"description,omitempty"`
	// FirstSeen indicates the beginning the time window during which the SDO
	// referenced by the SightingOf property was sighted.
	FirstSeen *Timestamp `json:"first_seen,omitempty"`
	// LastSeen indicates the end of the time window during which the SDO
	// referenced by the SightingOf property was sighted. If FirstSeen and
	// LastSeen are both defined, then LastSeen MUST be later than the
	// FirstSeen value.
	LastSeen *Timestamp `json:"last_seen,omitempty"`
	// Count if present, this MUST be an integer between 0 and 999,999,999
	// inclusive and represents the number of times the SDO referenced by the
	// SightingOf property was sighted. Observed Data has a similar property
	// called NumberObserved, which refers to the number of times the data was
	// observed. These counts refer to different concepts and are distinct. For
	// example, a single sighting of a DDoS bot might have many millions of
	// observations of the network traffic that it generates. Thus, the
	// Sighting count would be 1 (the bot was observed once) but the Observed
	// Data NumberObserved would be much higher. As another example, a sighting
	// with a count of 0 can be used to express that an indicator was not seen
	// at all.
	Count int64 `json:"count,omitempty"`
	// SightingOf is an  ID reference to the SDO that was sighted (e.g.,
	// Indicator or Malware). For example, if this is a Sighting of an
	// Indicator, that Indicator’s ID would be the value of this property. This
	// property MUST reference only an SDO or a Custom Object.  ObservedData
	// (optional) list of type identifier. A list of ID references to the
	// Observed Data objects that contain the raw cyber data for this Sighting.
	// For example, a Sighting of an Indicator with an IP address could include
	// the Observed Data for the network connection that the Indicator was used
	// to detect. This property MUST reference only Observed Data SDOs.
	SightingOf Identifier `json:"sighting_of_ref"`
	// ObservedData is a list of ID references to the Observed Data objects
	// that contain the raw cyber data for this Sighting. For example, a
	// Sighting of an Indicator with an IP address could include the Observed
	// Data for the network connection that the Indicator was used to detect.
	// This property MUST reference only Observed Data SDOs.
	ObservedData []Identifier `json:"observed_data_refs,omitempty"`
	// WhereSighted is a list of ID references to the Identity or Location
	// objects describing the entities or types of entities that saw the
	// sighting. Omitting the WhereSighted property does not imply that the
	// sighting was seen by the object creator. To indicate that the sighting
	// was seen by the object creator, an Identity representing the object
	// creator should be listed in WhereSighted. This property MUST reference
	// only Identity or Location SDOs.
	WhereSighted []Identifier `json:"where_sighted_refs,omitempty"`
	// Summary indicates whether the Sighting should be considered summary
	// data. Summary data is an aggregation of previous Sightings reports and
	// should not be considered primary source data. Default value is false.
	Summary bool `json:"summary,omitempty"`
}

// NewSighting creates a new Sighting of seen (s) Identifier.  Function returns
// a wrapped error if ErrInvalidProperty if an optional property's value is
// invalid according to the spec.
func NewSighting(s Identifier, opts ...SightingOption) (*Sighting, error) {
	if s == "" {
		return nil, ErrPropertyMissing
	}
	id := NewIdentifier(TypeSighting)
	ts := &Timestamp{time.Now()}
	obj := &Sighting{
		STIXRelationshipObject: STIXRelationshipObject{
			Type:        TypeSighting,
			ID:          id,
			SpecVersion: "2.1",
			Created:     ts,
			Modified:    ts,
		},
		SightingOf: s,
	}

	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(obj)
	}

	// Validation
	if obj.Count < 0 || obj.Count > 999999999 {
		return nil, fmt.Errorf("%w: Count %d out of bounds", ErrInvalidProperty, obj.Count)
	}
	if (obj.FirstSeen != nil && obj.LastSeen != nil) && obj.FirstSeen.After(obj.LastSeen.Time) {
		return nil, fmt.Errorf("%w: Last seen (%s) is before first seen (%s)", ErrInvalidProperty, obj.LastSeen, obj.FirstSeen)
	}

	// TODO: add check that SightingOf points to SDO or custom object.
	// TODO: add check that ObservedData points to Observed Data SDOs.
	// TODO: add check that WhereSighted points to Identity or Location SDOs.

	return obj, nil
}

/*
	Base object options
*/

// SightingOption is an optional parameter when constructing a
// Sighting object.
type SightingOption func(r *Sighting)

// SightingOptionSpecVersion sets the STIX spec version.
func SightingOptionSpecVersion(ver string) SightingOption {
	return func(r *Sighting) {
		r.SpecVersion = ver
	}
}

// SightingOptionExternalReferences sets the external references attribute.
func SightingOptionExternalReferences(refs []*ExternalReference) SightingOption {
	return func(r *Sighting) {
		r.ExternalReferences = refs
	}
}

// SightingOptionObjectMarking sets the object marking attribute.
func SightingOptionObjectMarking(om []Identifier) SightingOption {
	return func(r *Sighting) {
		r.ObjectMarking = om
	}
}

// SightingOptionGranularMarking sets the granular marking attribute.
func SightingOptionGranularMarking(gm *GranularMarking) SightingOption {
	return func(r *Sighting) {
		r.GranularMarking = gm
	}
}

// SightingOptionLang sets the lang attribute.
func SightingOptionLang(lang string) SightingOption {
	return func(r *Sighting) {
		r.Lang = lang
	}
}

// SightingOptionConfidence sets the confidence attribute.
func SightingOptionConfidence(confidence int) SightingOption {
	return func(r *Sighting) {
		r.Confidence = confidence
	}
}

// SightingOptionLables sets the lables attribute.
func SightingOptionLables(lables []string) SightingOption {
	return func(r *Sighting) {
		r.Lables = lables
	}
}

// SightingOptionRevoked sets the revoked attribute.
func SightingOptionRevoked(rev bool) SightingOption {
	return func(r *Sighting) {
		r.Revoked = rev
	}
}

// SightingOptionModified sets the modified attribute.
func SightingOptionModified(t *Timestamp) SightingOption {
	return func(r *Sighting) {
		r.Modified = t
	}
}

// SightingOptionCreated sets the created attribute.
func SightingOptionCreated(t *Timestamp) SightingOption {
	return func(r *Sighting) {
		r.Created = t
	}
}

// SightingOptionCreatedBy sets the created by by attribute.
func SightingOptionCreatedBy(id Identifier) SightingOption {
	return func(r *Sighting) {
		r.CreatedBy = id
	}
}

/*
	Sighting object options
*/

// SightingOptionDesciption sets the description attribute.
func SightingOptionDesciption(des string) SightingOption {
	return func(r *Sighting) {
		r.Description = des
	}
}

// SightingOptionFirstSeen sets the first seen attribute.
func SightingOptionFirstSeen(t *Timestamp) SightingOption {
	return func(r *Sighting) {
		r.FirstSeen = t
	}
}

// SightingOptionLastSeen sets the last seen attribute.
func SightingOptionLastSeen(t *Timestamp) SightingOption {
	return func(r *Sighting) {
		r.LastSeen = t
	}
}

// SightingOptionCount sets the count attribute.
func SightingOptionCount(c int64) SightingOption {
	return func(r *Sighting) {
		r.Count = c
	}
}

// SightingOptionObservedData sets the ObservedData attribute.
func SightingOptionObservedData(d []Identifier) SightingOption {
	return func(r *Sighting) {
		r.ObservedData = d
	}
}

// SightingOptionWhereSighted sets the WhereSighted attribute.
func SightingOptionWhereSighted(i []Identifier) SightingOption {
	return func(r *Sighting) {
		r.WhereSighted = i
	}
}

// SightingOptionSummary sets the summary attribute.
func SightingOptionSummary(b bool) SightingOption {
	return func(r *Sighting) {
		r.Summary = b
	}
}
