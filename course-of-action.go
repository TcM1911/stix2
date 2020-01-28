// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import "fmt"

// CourseOfAction (CoA) is a recommendation from a producer of intelligence to
// a consumer on the actions that they might take in response to that
// intelligence. The CoA may be preventative to deter exploitation or
// corrective to counter its potential impact. The CoA may describe automatable
// actions (applying patches, configuring firewalls, etc.), manual processes,
// or a combination of the two. For example, a CoA that describes how to
// remediate a vulnerability could describe how to apply the patch that removes
// that vulnerability.
type CourseOfAction struct {
	*STIXDomainObject
	// Name used to identify the Course of Action.
	Name string `json:"name"`
	// Description provides more details and context about the Course of
	// Action, potentially including its purpose and its key characteristics.
	// In some cases, this property may contain the actual course of action in
	// prose text.
	Description string `json:"description,omitempty"`
	// ActionType is the type of action that is included in either the
	// action_bin property or the dereferenced content from the
	// action_reference property. For example: textual:text/plain
	//
	// This is an open vocabulary and values SHOULD come from the
	// CourseOfActionTypes vocabulary.
	ActionType string `json:"action_type,omitempty"`
	// OSExecutionEnvs is a recommendation on the operating system(s) that this
	// course of action can be applied to. If no OSExecutionEnvs are defined,
	// the operating systems for the action specified by the ActionType
	// property are undefined, or the specific operating system has no impact
	// on the execution of the course of action (e.g., power off system). Each
	// string value for this property SHOULD be a CPE v2.3 entry from the
	// official NVD CPE Dictionary [NVD]. This property MAY include custom
	// values including values taken from other standards such as SWID.
	OSExecutionEnvs []string `json:"os_execution_envs,omitempty"`
	// ActionBin contains the base64 encoded "commands" that represent the
	// action for this Course of Action. This property MUST NOT be present if
	// ActionReference is provided.
	ActionBin string `json:"action_bin,omitempty"`
	// ActionReference is a valid external eference that resolves to the action
	// content as defined by the action_type property. This property MUST NOT
	// be present if action_bin is provided.
	ActionReference *ExternalReference `json:"action_reference,omitempty"`
}

// AddInvestigates creates an investigate relationship between the course of
// action and an indicator.
func (c *CourseOfAction) AddInvestigates(id Identifier, opts ...RelationshipOption) (*Relationship, error) {
	if !IsValidIdentifier(id) || !id.ForType(TypeIndicator) {
		return nil, ErrInvalidParameter
	}
	return NewRelationship(RelationshipTypeTargets, c.ID, id, opts...)
}

// AddMitigates creates a relationship to an attack pattern, indicator,
// malware, tool, or vulnerability that are mitigated by the object.
func (c *CourseOfAction) AddMitigates(id Identifier, opts ...RelationshipOption) (*Relationship, error) {
	if !IsValidIdentifier(id) || (!id.ForType(TypeAttackPattern) && !id.ForType(TypeIndicator) && !id.ForType(TypeMalware) && !id.ForType(TypeTool) && !id.ForType(TypeVulnerability)) {
		return nil, ErrInvalidParameter
	}
	return NewRelationship(RelationshipTypeTargets, c.ID, id, opts...)
}

// AddRemediates creates a relationship to a malware or a vulnerability that
// are remediated by the object.
func (c *CourseOfAction) AddRemediates(id Identifier, opts ...RelationshipOption) (*Relationship, error) {
	if !IsValidIdentifier(id) || (!id.ForType(TypeMalware) && !id.ForType(TypeVulnerability)) {
		return nil, ErrInvalidParameter
	}
	return NewRelationship(RelationshipTypeTargets, c.ID, id, opts...)
}

const (
	// CourseOfActionTypePlain is unstructured textual/prose description of a
	// course of action that does not conform to any standard language
	CourseOfActionTypePlain = "textual:text/plain"
	// CourseOfActionTypeHTML is prose description of a course of action
	// defined in structured HTML content
	CourseOfActionTypeHTML = "textual:text/html"
	// CourseOfActionTypeMD is prose description of a course of action defined
	// in structured markdown content
	CourseOfActionTypeMD = "textual:text/md"
	// CourseOfActionTypePDF is prose description of a course of action defined
	// in structured PDF content
	CourseOfActionTypePDF = "textual:pdf"
)

// NewCourseOfAction creates a new CourseOfAction object.
func NewCourseOfAction(name string, opts ...CourseOfActionOption) (*CourseOfAction, error) {
	if name == "" {
		return nil, ErrPropertyMissing
	}
	base := newSTIXDomainObject(TypeCourseOfAction)
	obj := &CourseOfAction{STIXDomainObject: base, Name: name}

	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(obj)
	}

	// Validate
	if obj.ActionBin != "" && obj.ActionReference != nil {
		return nil, fmt.Errorf("%w: both ActionBin and ActionReference must not be present at the same time", ErrInvalidParameter)
	}

	return obj, nil
}

// CourseOfActionOption is an optional parameter when constructing a
// CourseOfAction object.
type CourseOfActionOption func(a *CourseOfAction)

/*
	Base object options
*/

// CourseOfActionOptionSpecVersion sets the STIX spec version.
func CourseOfActionOptionSpecVersion(ver string) CourseOfActionOption {
	return func(obj *CourseOfAction) {
		obj.SpecVersion = ver
	}
}

// CourseOfActionOptionExternalReferences sets the external references attribute.
func CourseOfActionOptionExternalReferences(refs []*ExternalReference) CourseOfActionOption {
	return func(obj *CourseOfAction) {
		obj.ExternalReferences = refs
	}
}

// CourseOfActionOptionObjectMarking sets the object marking attribute.
func CourseOfActionOptionObjectMarking(om []Identifier) CourseOfActionOption {
	return func(obj *CourseOfAction) {
		obj.ObjectMarking = om
	}
}

// CourseOfActionOptionGranularMarking sets the granular marking attribute.
func CourseOfActionOptionGranularMarking(gm *GranularMarking) CourseOfActionOption {
	return func(obj *CourseOfAction) {
		obj.GranularMarking = gm
	}
}

// CourseOfActionOptionLang sets the lang attribute.
func CourseOfActionOptionLang(lang string) CourseOfActionOption {
	return func(obj *CourseOfAction) {
		obj.Lang = lang
	}
}

// CourseOfActionOptionConfidence sets the confidence attribute.
func CourseOfActionOptionConfidence(confidence int) CourseOfActionOption {
	return func(obj *CourseOfAction) {
		obj.Confidence = confidence
	}
}

// CourseOfActionOptionLables sets the lables attribute.
func CourseOfActionOptionLables(lables []string) CourseOfActionOption {
	return func(obj *CourseOfAction) {
		obj.Lables = lables
	}
}

// CourseOfActionOptionRevoked sets the revoked attribute.
func CourseOfActionOptionRevoked(rev bool) CourseOfActionOption {
	return func(obj *CourseOfAction) {
		obj.Revoked = rev
	}
}

// CourseOfActionOptionModified sets the modified attribute.
func CourseOfActionOptionModified(t *Timestamp) CourseOfActionOption {
	return func(obj *CourseOfAction) {
		obj.Modified = t
	}
}

// CourseOfActionOptionCreated sets the created attribute.
func CourseOfActionOptionCreated(t *Timestamp) CourseOfActionOption {
	return func(obj *CourseOfAction) {
		obj.Created = t
	}
}

// CourseOfActionOptionCreatedBy sets the created by by attribute.
func CourseOfActionOptionCreatedBy(id Identifier) CourseOfActionOption {
	return func(obj *CourseOfAction) {
		obj.CreatedBy = id
	}
}

/*
	CourseOfAction object options
*/

// CourseOfActionOptionDesciption sets the description attribute.
func CourseOfActionOptionDesciption(des string) CourseOfActionOption {
	return func(obj *CourseOfAction) {
		obj.Description = des
	}
}

// CourseOfActionOptionActionType sets the action type attribute.
func CourseOfActionOptionActionType(s string) CourseOfActionOption {
	return func(obj *CourseOfAction) {
		obj.ActionType = s
	}
}

// CourseOfActionOptionOSExecutionEnvs sets the OS execution envs attribute.
func CourseOfActionOptionOSExecutionEnvs(s []string) CourseOfActionOption {
	return func(obj *CourseOfAction) {
		obj.OSExecutionEnvs = s
	}
}

// CourseOfActionOptionActionBin sets the action bin attribute.
func CourseOfActionOptionActionBin(s string) CourseOfActionOption {
	return func(obj *CourseOfAction) {
		obj.ActionBin = s
	}
}

// CourseOfActionOptionActionReference sets the action reference attribute.
func CourseOfActionOptionActionReference(r *ExternalReference) CourseOfActionOption {
	return func(obj *CourseOfAction) {
		obj.ActionReference = r
	}
}
