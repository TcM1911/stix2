// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import "fmt"

// Campaign is a grouping of adversarial behaviors that describes a set of
// malicious activities or attacks (sometimes called waves) that occur over a
// period of time against a specific set of targets. Campaigns usually have
// well defined objectives and may be part of an Intrusion Set. Campaigns are
// often attributed to an intrusion set and threat actors. The threat actors
// may reuse known infrastructure from the intrusion set or may set up new
// infrastructure specific for conducting that campaign. Campaigns can be
// characterized by their objectives and the incidents they cause, people or
// resources they target, and the resources (infrastructure, intelligence,
// Malware, Tools, etc.) they use. For example, a Campaign could be used to
// describe a crime syndicate's attack using a specific variant of malware and
// new C2 servers against the executives of ACME Bank during the summer of 2016
// in order to gain secret information about an upcoming merger with another
// bank.
type Campaign struct {
	STIXDomainObject
	// Name used to identify the Campaign.
	Name string `json:"name"`
	// Description provides more details and context about the Campaign,
	// potentially including its purpose and its key characteristics.
	Description string `json:"description,omitempty"`
	// Aliases are a lternative names used to identify this Campaign
	Aliases []string `json:"aliases,omitempty"`
	// FirstSeen is the time that this Campaign was first seen.
	FirstSeen *Timestamp `json:"first_seen,omitempty"`
	// LastSeen is the time that this Campaign was last seen.
	LastSeen *Timestamp `json:"last_seen,omitempty"`
	// Objective defines the Campaign’s primary goal, objective, desired
	// outcome, or intended effect — what the Threat Actor or Intrusion Set
	// hopes to accomplish with this Campaign.
	Objective string `json:"objective,omitempty"`
}

// AddTargets creates a relationship to either an identity, location, or
// vulnerability that is targeted by this campaign.
func (c *Campaign) AddTargets(id Identifier, opts ...STIXOption) (*Relationship, error) {
	if !IsValidIdentifier(id) || (!id.ForType(TypeLocation) &&
		!id.ForType(TypeIdentity)) && !id.ForType(TypeVulnerability) {
		return nil, ErrInvalidParameter
	}
	return NewRelationship(RelationshipTypeTargets, c.ID, id, opts...)
}

// AddUses creates a relationship to either a malware or tool that is used by
// the campaign
func (c *Campaign) AddUses(id Identifier, opts ...STIXOption) (*Relationship, error) {
	if !IsValidIdentifier(id) || (!id.ForType(TypeMalware) && !id.ForType(TypeTool)) {
		return nil, ErrInvalidParameter
	}
	return NewRelationship(RelationshipTypeTargets, c.ID, id, opts...)
}

// AddAttributedTo creates a relationship to either an intrusion set or a
// threat actor that is attributed to the campaign.
func (c *Campaign) AddAttributedTo(id Identifier, opts ...STIXOption) (*Relationship, error) {
	if !IsValidIdentifier(id) || (!id.ForType(TypeIntrusionSet) && !id.ForType(TypeThreatActor)) {
		return nil, ErrInvalidParameter
	}
	return NewRelationship(RelationshipTypeTargets, c.ID, id, opts...)
}

// AddCompromises creates a relationship to an infrastructure that is
// compromised as part of the campaign.
func (c *Campaign) AddCompromises(id Identifier, opts ...STIXOption) (*Relationship, error) {
	if !IsValidIdentifier(id) || !id.ForType(TypeInfrastructure) {
		return nil, ErrInvalidParameter
	}
	return NewRelationship(RelationshipTypeTargets, c.ID, id, opts...)
}

// AddOriginatesFrom creates a relationship to a location that the campaign
// originates from the related location.
func (c *Campaign) AddOriginatesFrom(id Identifier, opts ...STIXOption) (*Relationship, error) {
	if !IsValidIdentifier(id) || !id.ForType(TypeLocation) {
		return nil, ErrInvalidParameter
	}
	return NewRelationship(RelationshipTypeTargets, c.ID, id, opts...)
}

// NewCampaign creates a new Campaign object.
func NewCampaign(name string, opts ...STIXOption) (*Campaign, error) {
	if name == "" {
		return nil, ErrPropertyMissing
	}
	base := newSTIXDomainObject(TypeCampaign)
	obj := &Campaign{STIXDomainObject: base, Name: name}

	err := applyOptions(obj, opts)

	if (obj.FirstSeen != nil && obj.LastSeen != nil) && obj.FirstSeen.After(obj.LastSeen.Time) {
		return nil, fmt.Errorf("%w: Last seen (%s) is before first seen (%s)", ErrInvalidProperty, obj.LastSeen, obj.FirstSeen)
	}

	return obj, err
}
