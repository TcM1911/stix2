// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

// Report is a collection of threat intelligence focused on one or more
// topics, such as a description of a threat actor, malware, or attack
// technique, including context and related details. They are used to group
// related threat intelligence together so that it can be published as a
// comprehensive cyber threat story.
//
// The Report SDO contains a list of references to STIX Objects (the CTI
// objects included in the report) along with a textual description and the
// name of the report.
//
// For example, a threat report produced by ACME Defense Corp. discussing the
// Glass Gazelle campaign should be represented using Report. The Report itself
// would contain the narrative of the report while the Campaign SDO and any
// related SDOs (e.g., Indicators for the Campaign, Malware it uses, and the
// associated Relationships) would be referenced in the report contents.
type Report struct {
	STIXDomainObject
	// Name is used to identify the Report.
	Name string `json:"name"`
	// Description that provides more details and context about the Report,
	// potentially including its purpose and its key characteristics.
	Description string `json:"description,omitempty"`
	// Types is an open vocabulary that specifies the primary subject(s) of
	// this report.
	Types []string `json:"report_types,omitempty"`
	// Published is the date that this Report object was officially published
	// by the creator of this report.
	Published *Timestamp `json:"published"`
	// Objects specifies the STIX Objects that are referred to by this Report.
	Objects []Identifier `json:"object_refs"`
}

func (o *Report) MarshalJSON() ([]byte, error) {
	return marshalToJSONHelper(o)
}

// NewReport creates a new Report object.
func NewReport(name string, published *Timestamp, objects []Identifier, opts ...STIXOption) (*Report, error) {
	if name == "" || published == nil || len(objects) == 0 {
		return nil, ErrPropertyMissing
	}
	base := newSTIXDomainObject(TypeReport)
	obj := &Report{
		STIXDomainObject: base,
		Name:             name,
		Published:        published,
		Objects:          objects,
	}

	err := applyOptions(obj, opts)
	return obj, err
}

const (
	// ReportTypeAttackPattern subject is a characterization of one or more
	// attack patterns and related information.
	ReportTypeAttackPattern = "attack-pattern"
	// ReportTypeCampaign subject is a characterization of one or more
	// campaigns and related information.
	ReportTypeCampaign = "campaign"
	// ReportTypeIdentity subject is a characterization of one or more
	// identities and related information.
	ReportTypeIdentity = "identity"
	// ReportTypeIndicator subject is a characterization of one or more
	// indicators and related information.
	ReportTypeIndicator = "indicator"
	// ReportTypeIntrusionSet subject is a characterization of one or more
	// intrusion sets and related information.
	ReportTypeIntrusionSet = "intrusion-set"
	// ReportTypeMalware subject is a characterization of one or more malware
	// instances and related information.
	ReportTypeMalware = "malware"
	// ReportTypeObservedData subject is a characterization of observed data
	// and related information.
	ReportTypeObservedData = "observed-data"
	// ReportTypeThreatActor subject is a characterization of one or more
	// threat actors and related information.
	ReportTypeThreatActor = "threat-actor"
	// ReportTypeThreatReport subject is a broad characterization of a threat
	// across multiple facets.
	ReportTypeThreatReport = "threat-report"
	// ReportTypeTool subject is a characterization of one or more tools and
	// related information.
	ReportTypeTool = "tool"
	// ReportTypeVulnerability subject is a characterization of one or more
	// vulnerabilities and related information.
	ReportTypeVulnerability = "vulnerability"
)
