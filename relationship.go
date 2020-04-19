// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

// Relationship object is used to link together two SDOs or SCOs in order to
// describe how they are related to each other. If SDOs and SCOs are considered
// "nodes" or "vertices" in the graph, the Relationship Objects (SROs)
// represent "edges".
//
// STIX defines many relationship types to link together SDOs and SCOs. These
// relationships are contained in the "Relationships" table under each SDO and
// SCO definition. Relationship types defined in the specification SHOULD be
// used to ensure consistency. An example of a specification-defined
// relationship is that an indicator indicates a campaign. That relationship
// type is listed in the Relationships section of the Indicator SDO definition.
//
// STIX also allows relationships from any SDO or SCO to any SDO or SCO that
// have not been defined in this specification. These relationships MAY use the
// related-to relationship type or MAY use a user-defined relationship type. As
// an example, a user might want to link malware directly to a tool. They can
// do so using related-to to say that the Malware is related to the Tool but
// not describe how, or they could use delivered-by (a user-defined name they
// determined) to indicate more detail.
type Relationship struct {
	STIXRelationshipObject
	// The name used to identify the type of Relationship. This value SHOULD be
	// an exact value listed in the relationships for the source and target
	// SDO, but MAY be any string. The value of this property MUST be in ASCII
	// and is limited to characters a–z (lowercase ASCII), 0–9, and hyphen (-).
	RelationshipType RelationshipType `json:"relationship_type"`
	// A description that provides more details and context about the
	// Relationship, potentially including its purpose and its key
	// characteristics.
	Description string `json:"description,omitempty"`
	// The id of the source (from) object. The value MUST be an ID reference to
	// an SDO or SCO (i.e., it cannot point to an SRO, Bundle, Language
	// Content,or Marking Definition).
	Source Identifier `json:"source_ref"`
	// The id of the target (to) object. The value MUST be an ID reference to
	// an SDO or SCO (i.e., it cannot point to an SRO, Bundle, Language
	// Content, or Marking Definition).
	Target Identifier `json:"target_ref"`
	// This optional timestamp represents the earliest time at which the
	// Relationship between the objects exists. If this property is a future
	// timestamp, at the time the start_time property is defined, then this
	// represents an estimate by the producer of the intelligence of the
	// earliest time at which relationship will be asserted to be true. If it
	// is not specified, then the earliest time at which the relationship
	// between the objects exists is not defined.
	StartTime *Timestamp `json:"start_time,omitempty"`
	// The latest time at which the Relationship between the objects exists. If
	// this property is a future timestamp, at the time the stop_time property
	// is defined, then this represents an estimate by the producer of the
	// intelligence of the latest time at which relationship will be asserted
	// to be true. If start_time and stop_time are both defined, then stop_time
	// MUST be later than the start_time value. If stop_time is not specified,
	// then the latest time at which the relationship between the objects
	// exists is either not known, not disclosed, or has no defined stop time.
	StopTime *Timestamp `json:"stop_time,omitempty"`
}

// NewRelationship creates a new Relationship object.
func NewRelationship(relType RelationshipType, source, target Identifier, opts ...RelationshipOption) (*Relationship, error) {
	if relType == "" || source == "" || target == "" {
		return nil, ErrPropertyMissing
	}
	base := newSTIXRelationshipObject(TypeRelationship)
	r := &Relationship{
		STIXRelationshipObject: base,
		Source:                 source,
		Target:                 target,
		RelationshipType:       relType,
	}

	// Set all optional parameters.
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(r)
	}
	return r, nil
}

// RelationshipType describes how the source and the target are related.
type RelationshipType string

const (
	// RelationshipTypeAVAnalysisOf is an AV analysis of relationship.
	RelationshipTypeAVAnalysisOf RelationshipType = "av-analysis-of"
	// RelationshipTypeAttrubutedTo is an attributed to relationship.
	RelationshipTypeAttrubutedTo RelationshipType = "attributed-to"
	// RelationshipTypeAuthoredBy is an authored by relationship.
	RelationshipTypeAuthoredBy RelationshipType = "authored-by"
	// RelationshipTypeBasedOn is a based on relationship.
	RelationshipTypeBasedOn RelationshipType = "based-on"
	// RelationshipTypeBeaconsTo is a beacons to relationship.
	RelationshipTypeBeaconsTo RelationshipType = "beacons-to"
	// RelationshipTypeBelongsTo is a belongs to relationship.
	RelationshipTypeBelongsTo RelationshipType = "belongs-to"
	// RelationshipTypeCharacterizes is a characterizes relationship.
	RelationshipTypeCharacterizes RelationshipType = "characterizes"
	// RelationshipTypeCommunicatesWith is a communicates with relationship.
	RelationshipTypeCommunicatesWith RelationshipType = "communicates-with"
	// RelationshipTypeCompromises is a compromises relationship.
	RelationshipTypeCompromises RelationshipType = "compromises"
	// RelationshipTypeConsistsOf is a consists of relationship.
	RelationshipTypeConsistsOf RelationshipType = "consists-of"
	// RelationshipTypeControls is a controls relationship.
	RelationshipTypeControls RelationshipType = "controls"
	// RelationshipTypeDelivers is a delivers relationship.
	RelationshipTypeDelivers RelationshipType = "delivers"
	// RelationshipTypeDerivedFrom is a derived from relationship.
	RelationshipTypeDerivedFrom RelationshipType = "derived-from"
	// RelationshipTypeDownloads is a downloads relationship.
	RelationshipTypeDownloads RelationshipType = "downloads"
	// RelationshipTypeDrops is a drops relationship.
	RelationshipTypeDrops RelationshipType = "drops"
	// RelationshipTypeDuplicateOf is a duplicate of relationship.
	RelationshipTypeDuplicateOf RelationshipType = "duplicate-of"
	// RelationshipTypeDynamicAnalysisOf is a dynamic analysis of relationship.
	RelationshipTypeDynamicAnalysisOf RelationshipType = "dynamic-analysis-of"
	// RelationshipTypeExfiltratesTo is an exfiltrates to relationship.
	RelationshipTypeExfiltratesTo RelationshipType = "exfiltrates-to"
	// RelationshipTypeExploits is a exploits relationship.
	RelationshipTypeExploits RelationshipType = "exploits"
	// RelationshipTypeHas is a has relationship.
	RelationshipTypeHas RelationshipType = "has"
	// RelationshipTypeHosts is a hosts relationship.
	RelationshipTypeHosts RelationshipType = "hosts"
	// RelationshipTypeImpersonates is an impersonates relationship.
	RelationshipTypeImpersonates RelationshipType = "impersonates"
	// RelationshipTypeIndicates is an indicates relationship.
	RelationshipTypeIndicates RelationshipType = "indicates"
	// RelationshipTypeLocatedAt is a located at relationship.
	RelationshipTypeLocatedAt RelationshipType = "located-at"
	// RelationshipTypeMitigates is a mitigates relationship.
	RelationshipTypeMitigates RelationshipType = "mitigates"
	// RelationshipTypeOriginatesFrom is an originates from relationship.
	RelationshipTypeOriginatesFrom RelationshipType = "originates-from"
	// RelationshipTypeOwns is an owns relationship.
	RelationshipTypeOwns RelationshipType = "owns"
	// RelationshipTypeRelatedTo is a related to relationship.
	RelationshipTypeRelatedTo RelationshipType = "related-to"
	// RelationshipTypeResolvesTo is a resolves to relationship.
	RelationshipTypeResolvesTo RelationshipType = "resolves-to"
	// RelationshipTypeStaticAnalysisOf is a static analysis of relationship.
	RelationshipTypeStaticAnalysisOf RelationshipType = "static-analysis-of"
	// RelationshipTypeTargets is a targets relationship.
	RelationshipTypeTargets RelationshipType = "targets"
	// RelationshipTypeUses is a uses relationship.
	RelationshipTypeUses RelationshipType = "uses"
	// RelationshipTypeVariantOf is a variant of relationship.
	RelationshipTypeVariantOf RelationshipType = "variant-of"
)

/*
	Base object options
*/

// RelationshipOption is an optional parameter when constructing a
// Relationship object.
type RelationshipOption func(r *Relationship)

// RelationshipOptionSpecVersion sets the STIX spec version.
func RelationshipOptionSpecVersion(ver string) RelationshipOption {
	return func(r *Relationship) {
		r.SpecVersion = ver
	}
}

// RelationshipOptionExternalReferences sets the external references attribute.
func RelationshipOptionExternalReferences(refs []*ExternalReference) RelationshipOption {
	return func(r *Relationship) {
		r.ExternalReferences = refs
	}
}

// RelationshipOptionObjectMarking sets the object marking attribute.
func RelationshipOptionObjectMarking(om []Identifier) RelationshipOption {
	return func(r *Relationship) {
		r.ObjectMarking = om
	}
}

// RelationshipOptionGranularMarking sets the granular marking attribute.
func RelationshipOptionGranularMarking(gm []*GranularMarking) RelationshipOption {
	return func(r *Relationship) {
		r.GranularMarking = gm
	}
}

// RelationshipOptionLang sets the lang attribute.
func RelationshipOptionLang(lang string) RelationshipOption {
	return func(r *Relationship) {
		r.Lang = lang
	}
}

// RelationshipOptionConfidence sets the confidence attribute.
func RelationshipOptionConfidence(confidence int) RelationshipOption {
	return func(r *Relationship) {
		r.Confidence = confidence
	}
}

// RelationshipOptionLabels sets the labels attribute.
func RelationshipOptionLabels(labels []string) RelationshipOption {
	return func(r *Relationship) {
		r.Labels = labels
	}
}

// RelationshipOptionRevoked sets the revoked attribute.
func RelationshipOptionRevoked(rev bool) RelationshipOption {
	return func(r *Relationship) {
		r.Revoked = rev
	}
}

// RelationshipOptionModified sets the modified attribute.
func RelationshipOptionModified(t *Timestamp) RelationshipOption {
	return func(r *Relationship) {
		r.Modified = t
	}
}

// RelationshipOptionCreated sets the created attribute.
func RelationshipOptionCreated(t *Timestamp) RelationshipOption {
	return func(r *Relationship) {
		r.Created = t
	}
}

// RelationshipOptionCreatedBy sets the created by by attribute.
func RelationshipOptionCreatedBy(id Identifier) RelationshipOption {
	return func(r *Relationship) {
		r.CreatedBy = id
	}
}

/*
	Relationship object options
*/

// RelationshipOptionDesciption sets the description attribute.
func RelationshipOptionDesciption(des string) RelationshipOption {
	return func(r *Relationship) {
		r.Description = des
	}
}

// RelationshipOptionStartTime sets the start time attribute.
func RelationshipOptionStartTime(t *Timestamp) RelationshipOption {
	return func(r *Relationship) {
		r.StartTime = t
	}
}

// RelationshipOptionStopTime sets the stop time attribute.
func RelationshipOptionStopTime(t *Timestamp) RelationshipOption {
	return func(r *Relationship) {
		r.StopTime = t
	}
}
