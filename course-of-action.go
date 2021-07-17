// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

// CourseOfAction (CoA) is a recommendation from a producer of intelligence to
// a consumer on the actions that they might take in response to that
// intelligence. The CoA may be preventative to deter exploitation or
// corrective to counter its potential impact. The CoA may describe automatable
// actions (applying patches, configuring firewalls, etc.), manual processes,
// or a combination of the two. For example, a CoA that describes how to
// remediate a vulnerability could describe how to apply the patch that removes
// that vulnerability.
type CourseOfAction struct {
	STIXDomainObject
	// Name used to identify the Course of Action.
	Name string `json:"name"`
	// Description provides more details and context about the Course of
	// Action, potentially including its purpose and its key characteristics.
	// In some cases, this property may contain the actual course of action in
	// prose text.
	Description string `json:"description,omitempty"`
}

func (o *CourseOfAction) MarshalJSON() ([]byte, error) {
	return marshalToJSONHelper(o)
}

// AddInvestigates creates an investigate relationship between the course of
// action and an indicator.
func (c *CourseOfAction) AddInvestigates(id Identifier, opts ...STIXOption) (*Relationship, error) {
	if !IsValidIdentifier(id) || !id.ForType(TypeIndicator) {
		return nil, ErrInvalidParameter
	}
	return NewRelationship(RelationshipTypeTargets, c.ID, id, opts...)
}

// AddMitigates creates a relationship to an attack pattern, indicator,
// malware, tool, or vulnerability that are mitigated by the object.
func (c *CourseOfAction) AddMitigates(id Identifier, opts ...STIXOption) (*Relationship, error) {
	if !IsValidIdentifier(id) || (!id.ForType(TypeAttackPattern) && !id.ForType(TypeIndicator) && !id.ForType(TypeMalware) && !id.ForType(TypeTool) && !id.ForType(TypeVulnerability)) {
		return nil, ErrInvalidParameter
	}
	return NewRelationship(RelationshipTypeTargets, c.ID, id, opts...)
}

// AddRemediates creates a relationship to a malware or a vulnerability that
// are remediated by the object.
func (c *CourseOfAction) AddRemediates(id Identifier, opts ...STIXOption) (*Relationship, error) {
	if !IsValidIdentifier(id) || (!id.ForType(TypeMalware) && !id.ForType(TypeVulnerability)) {
		return nil, ErrInvalidParameter
	}
	return NewRelationship(RelationshipTypeTargets, c.ID, id, opts...)
}

// NewCourseOfAction creates a new CourseOfAction object.
func NewCourseOfAction(name string, opts ...STIXOption) (*CourseOfAction, error) {
	if name == "" {
		return nil, ErrPropertyMissing
	}
	base := newSTIXDomainObject(TypeCourseOfAction)
	obj := &CourseOfAction{STIXDomainObject: base, Name: name}

	err := applyOptions(obj, opts)
	return obj, err
}
