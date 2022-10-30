// Copyright 2022 Patrick Bédat. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

// The Incident object in STIX 2.1 is a stub.
// It is included to support basic use cases but does not contain properties
// to represent metadata about incidents. Future STIX 2 releases will expand
// it to include these capabilities.
// It is suggested that it is used as an extension point for an Incident object
// defined using the extension facility described in section 7.3.
type Incident struct {
	STIXDomainObject
	// Name used to identify the Incident.
	Name string `json:"name"`
	// A description that provides more details and context about the Incident,
	// potentially including its purpose and its key characteristics.
	Description string `json:"description,omitempty"`
}

func (o *Incident) MarshalJSON() ([]byte, error) {
	return marshalToJSONHelper(o)
}

// NewCampaign creates a new Campaign object.
func NewIncident(name string, opts ...STIXOption) (*Incident, error) {
	if name == "" {
		return nil, ErrPropertyMissing
	}
	base := newSTIXDomainObject(TypeIncident)
	obj := &Incident{STIXDomainObject: base, Name: name}

	err := applyOptions(obj, opts)

	return obj, err
}
