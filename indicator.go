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
	// Types is an open vocabulary that specifies a set of
	// categorizations for this indicator.
	Types []string `json:"indicator_types,omitempty"`
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
	KillChainPhase []*KillChainPhase `json:"kill_chain_phases,omitempty"`
}

func (o *Indicator) MarshalJSON() ([]byte, error) {
	return marshalToJSONHelper(o)
}

// AddIndicates creates a relationship that describes that the Indicator can
// detect evidence of the related Attack Pattern, Campaign, Infrastructure,
// Intrusion Set, Malware, Threat Actor, or Tool. This evidence may not be
// direct: for example, the Indicator may detect secondary evidence of the
// Campaign, such as malware or behavior commonly used by that Campaign.
func (c *Indicator) AddIndicates(id Identifier, opts ...STIXOption) (*Relationship, error) {
	if !IsValidIdentifier(id) || !id.ForTypes(TypeAttackPattern, TypeCampaign, TypeInfrastructure, TypeIntrusionSet, TypeMalware, TypeThreatActor, TypeTool) {
		return nil, ErrInvalidParameter
	}
	return NewRelationship(RelationshipTypeIndicates, c.ID, id, opts...)
}

// AddBasedOn creates a relationship that describes hat the indicator was
// created based on information from an observed-data object.
func (c *Indicator) AddBasedOn(id Identifier, opts ...STIXOption) (*Relationship, error) {
	if !IsValidIdentifier(id) || !id.ForType(TypeObservedData) {
		return nil, ErrInvalidParameter
	}
	return NewRelationship(RelationshipTypeBasedOn, c.ID, id, opts...)
}

// NewIndicator creates a new Indicator object.
func NewIndicator(pattern, patternType string, validFrom *Timestamp, opts ...STIXOption) (*Indicator, error) {
	if pattern == "" || patternType == "" || validFrom == nil {
		return nil, ErrPropertyMissing
	}
	base := newSTIXDomainObject(TypeIndicator)
	obj := &Indicator{STIXDomainObject: base, Pattern: pattern, PatternType: patternType, ValidFrom: validFrom}

	err := applyOptions(obj, opts)
	return obj, err
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

const (
	// PatternTypeSTIX specifies the STIX pattern language.
	PatternTypeSTIX = "stix"
	// PatternTypePCRE specifies the Perl Compatible Regular Expressions
	// language.
	PatternTypePCRE = "pcre"
	// PatternTypeSigma specifies the SIGMA language.
	PatternTypeSigma = "sigma"
	// PatternTypeSnort specifies the SNORT language.
	PatternTypeSnort = "snort"
	// PatternTypeSuricata specifies the SURICATA language.
	PatternTypeSuricata = "suricata"
	// PatternTypeYara specifies the YARA language.
	PatternTypeYara = "yara"
)
