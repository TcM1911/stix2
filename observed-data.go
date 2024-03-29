// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

// ObservedData conveys information about cyber security related entities such
// as files, systems, and networks using the STIX Cyber-observable Objects
// (SCOs). For example, ObservedData can capture information about an IP
// address, a network connection, a file, or a registry key. ObservedData is
// not an intelligence assertion, it is simply the raw information without any
// context for what it means.
//
// ObservedData can capture that a piece of information was seen one or more
// times. Meaning, it can capture both a single observation of a single entity
// (file, network connection) as well as the aggregation of multiple
// observations of an entity. When the NumberObserved property is 1 the
// ObservedData represents a single entity. When the NumberObserved property is
// greater than 1, the ObservedData represents several instances of an entity
// potentially collected over a period of time. If a time window is known, that
// can be captured using the FirstObserved and LastObserved properties. When
// used to collect aggregate data, it is likely that some properties in the SCO
// (e.g., timestamp properties) will be omitted because they would differ for
// each of the individual observations.
//
// ObservedData may be used by itself (without relationships) to convey raw
// data collected from any source including analyst reports, sandboxes, and
// network and host-based detection tools. An intelligence producer conveying
// ObservedData SHOULD include as much context (e.g. SCOs) as possible that
// supports the use of the observed data set in systems expecting to utilize
// the ObservedData for improved security. This includes all SCOs that matched
// on an Indicator pattern and are represented in the collected observed event
// (or events) being conveyed in the ObservedData object. For example, a
// firewall could emit a single ObservedData instance containing a single
// Network Traffic object for each connection it sees. The firewall could also
// aggregate data and instead send out an ObservedData instance every ten
// minutes with an IP address and an appropriate NumberObserved value to
// indicate the number of times that IP address was observed in that window. A
// sandbox could emit an ObservedData instance containing a file hash that it
// discovered.
//
// ObservedData may also be related to other SDOs to represent raw data that is
// relevant to those objects. For example, the Sighting Relationship object,
// can relate an Indicator, Malware, or other SDO to a specific ObservedData to
// represent the raw information that led to the creation of the Sighting
// (e.g., what was actually seen that suggested that a particular instance of
// malware was active).
//
// To support backwards compatibility, related SCOs can still be specified
// using the Objects properties, Either the objects property or the ObjectRefs
// property MUST be provided, but both MUST NOT be present at the same time.
type ObservedData struct {
	STIXDomainObject
	// FirstObserved is the beginning of the time window during which the data
	// was seen.
	FirstObserved *Timestamp `json:"first_observed"`
	// LastObserved is the end of the time window during which the data was
	// seen.
	LastObserved *Timestamp `json:"last_observed"`
	// NumberObserved is the number of times that each Cyber-observable object
	// represented in the objects or object_ref property was seen. If present,
	// this MUST be an integer between 1 and 999,999,999 inclusive.
	NumberObserved int64 `json:"number_observed"`
	// Objects is a map of SCO representing the observation. The dictionary
	// MUST contain at least one object. The cyber observable content MAY
	// include multiple objects if those objects are related as part of a
	// single observation. Multiple objects not related to each other via cyber
	// observable Relationships MUST NOT be contained within the same
	// ObservedData instance. This property MUST NOT be present if ObjectRefs
	// is provided. For example, a Network Traffic object and two IPv4 Address
	// objects related via the src_ref and dst_ref properties can be contained
	// in the same Observed Data because they are all related and used to
	// characterize that single entity.
	//
	// NOTE: this property is now deprecated in favor of ObjectRefs and will be
	// removed in a future version.
	Objects map[string]*STIXCyberObservableObject `json:"objects,omitempty"`
	// ObjectRefs is a list of SCOs and SROs representing the observation. The
	// ObjectRefs MUST contain at least one SCO reference if defined.
	ObjectRefs []Identifier `json:"object_refs,omitempty"`
}

func (o *ObservedData) MarshalJSON() ([]byte, error) {
	return marshalToJSONHelper(o)
}

// NewObservedData creates a new ObservedData object.
func NewObservedData(firstObserved, lastObserved *Timestamp, numberObserved int64, objectsRef []Identifier, opts ...STIXOption) (*ObservedData, error) {
	if len(objectsRef) == 0 || firstObserved == nil || lastObserved == nil || numberObserved < 1 {
		return nil, ErrPropertyMissing
	}
	base := newSTIXDomainObject(TypeObservedData)
	obj := &ObservedData{
		STIXDomainObject: base,
		FirstObserved:    firstObserved,
		LastObserved:     lastObserved,
		NumberObserved:   numberObserved,
		ObjectRefs:       objectsRef,
	}

	err := applyOptions(obj, opts)
	return obj, err
}
