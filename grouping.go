// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

// Grouping object explicitly asserts that the referenced STIX Objects have a
// shared context, unlike a STIX Bundle (which explicitly conveys no context).
// A Grouping object should not be confused with an intelligence product, which
// should be conveyed via a STIX Report.
//
// A STIX Grouping object might represent a set of data that, in time, given
// sufficient analysis, would mature to convey an incident or threat report as
// a STIX Report object. For example, a Grouping could be used to characterize
// an ongoing investigation into a security event or incident. A Grouping
// object could also be used to assert that the referenced STIX Objects are
// related to an ongoing analysis process, such as when a threat analyst is
// collaborating with others in their trust community to examine a series of
// Campaigns and Indicators. The Grouping SDO contains a list of references to
// SDOs, SCOs, and SROs, along with an explicit statement of the context shared
// by the content, a textual description, and the name of the grouping.
type Grouping struct {
	STIXDomainObject
	// Name is used to identify the Grouping.
	Name string `json:"name,omitempty"`
	// Description provides more details and context about the Grouping,
	// potentially including its purpose and its key characteristics.
	Description string `json:"description,omitempty"`
	// Context provides a short descriptor of the particular context shared by
	// the content referenced by the Grouping. This is an open vocabulary and
	// values SHOULD come from the GroupingContext constants.
	Context string `json:"context"`
	// Objects specifies the STIX Objects that are referred to by this
	// Grouping.
	Objects []Identifier `json:"object_refs"`
}

func (o *Grouping) MarshalJSON() ([]byte, error) {
	return marshalToJSONHelper(o)
}

// NewGrouping creates a new Grouping object.
func NewGrouping(context string, objects []Identifier, opts ...STIXOption) (*Grouping, error) {
	if context == "" || len(objects) < 1 {
		return nil, ErrPropertyMissing
	}
	base := newSTIXDomainObject(TypeGrouping)
	obj := &Grouping{STIXDomainObject: base, Context: context, Objects: objects}

	err := applyOptions(obj, opts)
	return obj, err
}

const (
	// GroupingContextSuspiciousActivity is a et of STIX content related to a
	// particular suspicious activity event.
	GroupingContextSuspiciousActivity = "suspicious-activity"
	// GroupingContextMalwareAnalysis is a set of STIX content related to a
	// particular malware instance or family.
	GroupingContextMalwareAnalysis = "malware-analysis"
	// GroupingContextUnspecified is a set of STIX content contextually related
	// but without any precise characterization of the contextual relationship
	// between the objects.
	GroupingContextUnspecified = "unspecified"
)
