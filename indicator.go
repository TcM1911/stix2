// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

// Indicator contain a pattern that can be used to detect suspicious or
// malicious cyber activity. For example, an Indicator may be used to represent
// a set of malicious domains and use the STIX Patterning Language to specify
// these domains. The Indicator SDO contains a simple textual description, the
// Kill Chain Phases that it detects behavior in, a time window for when the
// Indicator is valid or useful, and a required pattern property to capture a
// structured detection pattern. Relationships from the Indicator can describe
// the malicious or suspicious behavior that it directly detects (Malware,
// Tool, and Attack Pattern). In addition, it may also imply the presence of a
// Campaigns, Intrusion Sets, and Threat Actors, etc.
type Indicator struct {
	STIXDomainObject
	// Name is used to identify the Indicator. Producers SHOULD provide this
	// property to help products and analysts understand what this Indicator
	// actually does.
	Name string `json:"name,omitempty"`
	// Description provides more details and context about the Indicator,
	// potentially including its purpose and its key characteristics.
	Description string `json:"description,omitempty"`
	// IndicatorTypes is an open vocabulary that specifies a set of
	// categorizations for this indicator.
	IndicatorTypes []string `json:"indicator_types"`
	// Pattern is the detection pattern for this Indicator.
	Pattern string `json:"pattern"`
	// PatternType is the type of pattern used in this indicator. The property
	// is an open vocabulary and currently has the values of stix, snort, and
	// yara.
	PatternType string `json:"pattern_type"`
	// PatternVersion is the version of the pattern that is used. For patterns
	// that do not have a formal specification, the build or code version that
	// the pattern is known to work with SHOULD be used.
	PatternVersion string `json:"pattern_version,omitempty"`
	// ValidFrom is the time from which this Indicator is considered a valid
	// indicator of the behaviors it is related or represents.
	ValidFrom *Timestamp `json:"valid_from"`
	// ValidUntil is the time at which this Indicator should no longer
	// considered a valid indicator of the behaviors it is related to or
	// represents.
	ValidUntil *Timestamp `json:"valid_until,omitempty"`
	// KillChainPhases is the kill chain phase(s) to which this Indicator
	// corresponds.
	KillChainPhases []*KillChainPhase `json:"kill_chain_phases,omitempty"`
}

// AddIndicates creates a relationship that describes that the Indicator can
// detect evidence of the related Attack Pattern, Campaign, Infrastructure,
// Intrusion Set, Malware, Threat Actor, or Tool. This evidence may not be
// direct: for example, the Indicator may detect secondary evidence of the
// Campaign, such as malware or behavior commonly used by that Campaign.
func (c *Indicator) AddIndicates(id Identifier, opts ...RelationshipOption) (*Relationship, error) {
	if !IsValidIdentifier(id) || !id.ForTypes(TypeAttackPattern, TypeCampaign, TypeInfrastructure, TypeIntrusionSet, TypeMalware, TypeThreatActor, TypeTool) {
		return nil, ErrInvalidParameter
	}
	return NewRelationship(RelationshipTypeIndicates, c.ID, id, opts...)
}

// AddBasedOn creates a relationship that describes hat the indicator was
// created based on information from an observed-data object.
func (c *Indicator) AddBasedOn(id Identifier, opts ...RelationshipOption) (*Relationship, error) {
	if !IsValidIdentifier(id) || !id.ForType(TypeObservedData) {
		return nil, ErrInvalidParameter
	}
	return NewRelationship(RelationshipTypeBasedOn, c.ID, id, opts...)
}

// NewIndicator creates a new Indicator object.
func NewIndicator(pattern, patternType string, indicatorTypes []string, validFrom *Timestamp, opts ...IndicatorOption) (*Indicator, error) {
	if pattern == "" || patternType == "" || len(indicatorTypes) == 0 || validFrom == nil {
		return nil, ErrPropertyMissing
	}
	base := newSTIXDomainObject(TypeIndicator)
	obj := &Indicator{STIXDomainObject: base, Pattern: pattern, PatternType: patternType, IndicatorTypes: indicatorTypes, ValidFrom: validFrom}

	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(obj)
	}
	return obj, nil
}

const (
	// IndicatorTypeAnomalousActivity is unexpected, or unusual activity that
	// may not necessarily be malicious or indicate compromise. This type of
	// activity may include reconnaissance-like behavior such as port scans or
	// version identification, network behavior anomalies, and asset and/or
	// user behavioral anomalies.
	IndicatorTypeAnomalousActivity = "anomalous-activity"
	// IndicatorTypeAnonymization is a suspected anonymization tools or
	// infrastructure (proxy, TOR, VPN, etc.).
	IndicatorTypeAnonymization = "anonymization"
	// IndicatorTypeBenign is an activity that is not suspicious or malicious
	// in and of itself, but when combined with other activity may indicate
	// suspicious or malicious behavior.
	IndicatorTypeBenign = "benign"
	// IndicatorTypeCompromised is an assets that are suspected to be compromised.
	IndicatorTypeCompromised = "compromised"
	// IndicatorTypeMaliciousActivity is patterns of suspected malicious
	// objects and/or activity.
	IndicatorTypeMaliciousActivity = "malicious-activity"
	// IndicatorTypeAttribution is patterns of behavior that indicate
	// attribution to a particular Threat Actor or Campaign.
	IndicatorTypeAttribution = "attribution"
	// IndicatorTypeUnknown indicates there is not enough information available
	// to determine the type of indicator.
	IndicatorTypeUnknown = "unknown"
)

// IndicatorOption is an optional parameter when constructing a
// Indicator object.
type IndicatorOption func(a *Indicator)

/*
	Base object options
*/

// IndicatorOptionSpecVersion sets the STIX spec version.
func IndicatorOptionSpecVersion(ver string) IndicatorOption {
	return func(obj *Indicator) {
		obj.SpecVersion = ver
	}
}

// IndicatorOptionExternalReferences sets the external references attribute.
func IndicatorOptionExternalReferences(refs []*ExternalReference) IndicatorOption {
	return func(obj *Indicator) {
		obj.ExternalReferences = refs
	}
}

// IndicatorOptionObjectMarking sets the object marking attribute.
func IndicatorOptionObjectMarking(om []Identifier) IndicatorOption {
	return func(obj *Indicator) {
		obj.ObjectMarking = om
	}
}

// IndicatorOptionGranularMarking sets the granular marking attribute.
func IndicatorOptionGranularMarking(gm []*GranularMarking) IndicatorOption {
	return func(obj *Indicator) {
		obj.GranularMarking = gm
	}
}

// IndicatorOptionLang sets the lang attribute.
func IndicatorOptionLang(lang string) IndicatorOption {
	return func(obj *Indicator) {
		obj.Lang = lang
	}
}

// IndicatorOptionConfidence sets the confidence attribute.
func IndicatorOptionConfidence(confidence int) IndicatorOption {
	return func(obj *Indicator) {
		obj.Confidence = confidence
	}
}

// IndicatorOptionLabels sets the labels attribute.
func IndicatorOptionLabels(labels []string) IndicatorOption {
	return func(obj *Indicator) {
		obj.Labels = labels
	}
}

// IndicatorOptionRevoked sets the revoked attribute.
func IndicatorOptionRevoked(rev bool) IndicatorOption {
	return func(obj *Indicator) {
		obj.Revoked = rev
	}
}

// IndicatorOptionModified sets the modified attribute.
func IndicatorOptionModified(t *Timestamp) IndicatorOption {
	return func(obj *Indicator) {
		obj.Modified = t
	}
}

// IndicatorOptionCreated sets the created attribute.
func IndicatorOptionCreated(t *Timestamp) IndicatorOption {
	return func(obj *Indicator) {
		obj.Created = t
	}
}

// IndicatorOptionCreatedBy sets the created by by attribute.
func IndicatorOptionCreatedBy(id Identifier) IndicatorOption {
	return func(obj *Indicator) {
		obj.CreatedBy = id
	}
}

/*
	Indicator object options
*/

// IndicatorOptionDesciption sets the description attribute.
func IndicatorOptionDesciption(des string) IndicatorOption {
	return func(obj *Indicator) {
		obj.Description = des
	}
}

// IndicatorOptionKillChainPhase sets the kill chain phase attribute.
func IndicatorOptionKillChainPhase(s []*KillChainPhase) IndicatorOption {
	return func(obj *Indicator) {
		obj.KillChainPhases = s
	}
}

// IndicatorOptionName sets the name attribute.
func IndicatorOptionName(s string) IndicatorOption {
	return func(obj *Indicator) {
		obj.Name = s
	}
}

// IndicatorOptionPatternVersion sets the pattern version attribute.
func IndicatorOptionPatternVersion(s string) IndicatorOption {
	return func(obj *Indicator) {
		obj.PatternVersion = s
	}
}

// IndicatorOptionValidUntil sets the valid until attribute.
func IndicatorOptionValidUntil(t *Timestamp) IndicatorOption {
	return func(obj *Indicator) {
		obj.ValidUntil = t
	}
}
