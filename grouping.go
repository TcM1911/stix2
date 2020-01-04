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
	*STIXDomainObject
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

// NewGrouping creates a new Grouping object.
func NewGrouping(context string, objects []Identifier, opts ...GroupingOption) (*Grouping, error) {
	if context == "" || len(objects) < 1 {
		return nil, ErrPropertyMissing
	}
	base, err := newSTIXDomainObject(TypeGrouping)
	if err != nil {
		return nil, err
	}
	obj := &Grouping{STIXDomainObject: base, Context: context, Objects: objects}

	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(obj)
	}
	return obj, nil
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

// GroupingOption is an optional parameter when constructing a
// Grouping object.
type GroupingOption func(a *Grouping)

/*
	Base object options
*/

// GroupingOptionSpecVersion sets the STIX spec version.
func GroupingOptionSpecVersion(ver string) GroupingOption {
	return func(obj *Grouping) {
		obj.SpecVersion = ver
	}
}

// GroupingOptionExternalReferences sets the external references attribute.
func GroupingOptionExternalReferences(refs []*ExternalReference) GroupingOption {
	return func(obj *Grouping) {
		obj.ExternalReferences = refs
	}
}

// GroupingOptionObjectMarking sets the object marking attribute.
func GroupingOptionObjectMarking(om []Identifier) GroupingOption {
	return func(obj *Grouping) {
		obj.ObjectMarking = om
	}
}

// GroupingOptionGranularMarking sets the granular marking attribute.
func GroupingOptionGranularMarking(gm *GranularMarking) GroupingOption {
	return func(obj *Grouping) {
		obj.GranularMarking = gm
	}
}

// GroupingOptionLang sets the lang attribute.
func GroupingOptionLang(lang string) GroupingOption {
	return func(obj *Grouping) {
		obj.Lang = lang
	}
}

// GroupingOptionConfidence sets the confidence attribute.
func GroupingOptionConfidence(confidence int) GroupingOption {
	return func(obj *Grouping) {
		obj.Confidence = confidence
	}
}

// GroupingOptionLables sets the lables attribute.
func GroupingOptionLables(lables []string) GroupingOption {
	return func(obj *Grouping) {
		obj.Lables = lables
	}
}

// GroupingOptionRevoked sets the revoked attribute.
func GroupingOptionRevoked(rev bool) GroupingOption {
	return func(obj *Grouping) {
		obj.Revoked = rev
	}
}

// GroupingOptionModified sets the modified attribute.
func GroupingOptionModified(t *Timestamp) GroupingOption {
	return func(obj *Grouping) {
		obj.Modified = t
	}
}

// GroupingOptionCreated sets the created attribute.
func GroupingOptionCreated(t *Timestamp) GroupingOption {
	return func(obj *Grouping) {
		obj.Created = t
	}
}

// GroupingOptionCreatedBy sets the created by by attribute.
func GroupingOptionCreatedBy(id Identifier) GroupingOption {
	return func(obj *Grouping) {
		obj.CreatedBy = id
	}
}

/*
	Grouping object options
*/

// GroupingOptionDesciption sets the description attribute.
func GroupingOptionDesciption(des string) GroupingOption {
	return func(obj *Grouping) {
		obj.Description = des
	}
}

// GroupingOptionName sets the name attribute.
func GroupingOptionName(n string) GroupingOption {
	return func(obj *Grouping) {
		obj.Name = n
	}
}
