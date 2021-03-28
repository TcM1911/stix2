// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

// IntrusionSet is a grouped set of adversarial behaviors and resources with
// common properties that is believed to be orchestrated by a single
// organization. An IntrusionSet may capture multiple Campaigns or other
// activities that are all tied together by shared attributes indicating a
// common known or unknown Threat Actor. New activity can be attributed to an
// IntrusionSet even if the Threat Actors behind the attack are not known.
// Threat Actors can move from supporting one IntrusionSet to supporting
// another, or they may support multiple IntrusionSets.
//
// Where a Campaign is a set of attacks over a period of time against a
// specific set of targets to achieve some objective, an IntrusionSet is the
// entire attack package and may be used over a very long period of time in
// multiple Campaigns to achieve potentially multiple purposes.
//
// While sometimes an IntrusionSet is not active, or changes focus, it is
// usually difficult to know if it has truly disappeared or ended. Analysts may
// have varying level of fidelity on attributing an Intrusion Set back to
// Threat Actors and may be able to only attribute it back to a nation state or
// perhaps back to an organization within that nation state.
type IntrusionSet struct {
	STIXDomainObject
	// Name is used to identify this IntrusionSet.
	Name string `json:"name"`
	// Description provides more details and context about the Intrusion Set,
	// potentially including its purpose and its key characteristics.
	Description string `json:"description,omitempty"`
	// Aliases are alternative names used to identify this IntrusionSet.
	Aliases []string `json:"aliases,omitempty"`
	// FirstSeen is the time that this Intrusion Set was first seen. This
	// property is a summary property of data from sightings and other data
	// that may or may not be available in STIX. If new sightings are received
	// that are earlier than the first seen timestamp, the object may be
	// updated to account for the new data.
	FirstSeen *Timestamp `json:"first_seen,omitempty"`
	// LastSeen is the time that this Intrusion Set was last seen. This
	// property is a summary property of data from sightings and other data
	// that may or may not be available in STIX. If new sightings are received
	// that are later than the last seen timestamp, the object may be updated
	// to account for the new data.
	LastSeen *Timestamp `json:"last_seen,omitempty"`
	// Goals is the high-level goals of this Intrusion Set, namely, what are
	// they trying to do. For example, they may be motivated by personal gain,
	// but their goal is to steal credit card numbers. To do this, they may
	// execute specific Campaigns that have detailed objectives like
	// compromising point of sale systems at a large retailer. Another example:
	// to gain information about latest merger and IPO information from ACME
	// Bank.
	Goals []string `json:"goals,omitempty"`
	// ResourceLevel defines the organizational level at which this Intrusion
	// Set typically works, which in turn determines the resources available to
	// this Intrusion Set for use in an attack. This is an open vocabulary and
	// values SHOULD come from the AttackResourceLevel vocabulary.
	ResourceLevel string `json:"resource_level,omitempty"`
	// PrimaryMotivation is the primary reason, motivation, or purpose behind
	// this Intrusion Set. The motivation is why the Intrusion Set wishes to
	// achieve the goal (what they are trying to achieve). For example, an
	// Intrusion Set with a goal to disrupt the finance sector in a country
	// might be motivated by ideological hatred of capitalism. This is an open
	// vocabulary and values SHOULD come from the AttackMotivation vocabulary.
	PrimaryMotivation string `json:"primary_motivation,omitempty"`
	// SecondaryMotivation is the secondary reasons, motivations, or purposes
	// behind this Intrusion Set. These motivations can exist as an equal or
	// near-equal cause to the primary motivation. However, it does not replace
	// or necessarily magnify the primary motivation, but it might indicate
	// additional context. The position in the list has no significance. This
	// is an open vocabulary and values SHOULD come from the AttackMotivation
	// vocabulary.
	SecondaryMotivations []string `json:"secondary_motivations,omitempty"`
}

// AddAttributedTo describes that the related Threat Actor is involved in
// carrying out the Intrusion Set.
func (c *IntrusionSet) AddAttributedTo(id Identifier, opts ...STIXOption) (*Relationship, error) {
	if !IsValidIdentifier(id) || !id.ForType(TypeThreatActor) {
		return nil, ErrInvalidParameter
	}
	return NewRelationship(RelationshipTypeAttributedTo, c.ID, id, opts...)
}

// AddCompromises describes that the Intrusion Set compromises the related
// Infrastructure.
func (c *IntrusionSet) AddCompromises(id Identifier, opts ...STIXOption) (*Relationship, error) {
	if !IsValidIdentifier(id) || !id.ForType(TypeInfrastructure) {
		return nil, ErrInvalidParameter
	}
	return NewRelationship(RelationshipTypeCompromises, c.ID, id, opts...)
}

// AddHosts describes that the Intrusion Set hosts the related Infrastructure
// (e.g. an actor that rents botnets to other threat actors).
func (c *IntrusionSet) AddHosts(id Identifier, opts ...STIXOption) (*Relationship, error) {
	if !IsValidIdentifier(id) || !id.ForType(TypeInfrastructure) {
		return nil, ErrInvalidParameter
	}
	return NewRelationship(RelationshipTypeHosts, c.ID, id, opts...)
}

// AddOwns describes that the Intrusion Set owns the related Infrastructure
// (e.g. an actor that rents botnets to other threat actors).
func (c *IntrusionSet) AddOwns(id Identifier, opts ...STIXOption) (*Relationship, error) {
	if !IsValidIdentifier(id) || !id.ForType(TypeInfrastructure) {
		return nil, ErrInvalidParameter
	}
	return NewRelationship(RelationshipTypeOwns, c.ID, id, opts...)
}

// AddOriginatesFrom describes that the Intrusion Set originates from the
// related location and SHOULD NOT be used to define attribution.
func (c *IntrusionSet) AddOriginatesFrom(id Identifier, opts ...STIXOption) (*Relationship, error) {
	if !IsValidIdentifier(id) || !id.ForType(TypeLocation) {
		return nil, ErrInvalidParameter
	}
	return NewRelationship(RelationshipTypeOriginatesFrom, c.ID, id, opts...)
}

// AddTargets describes that the Intrusion Set uses exploits of the related
// Vulnerability or targets the type of victims described by the related
// Identity or Location.
func (c *IntrusionSet) AddTargets(id Identifier, opts ...STIXOption) (*Relationship, error) {
	if !IsValidIdentifier(id) || !id.ForTypes(TypeLocation, TypeIdentity, TypeVulnerability) {
		return nil, ErrInvalidParameter
	}
	return NewRelationship(RelationshipTypeTargets, c.ID, id, opts...)
}

// AddUses describes that attacks carried out as part of the Intrusion Set
// typically use the related Attack Pattern, Infrastructure, Malware, or Tool.
func (c *IntrusionSet) AddUses(id Identifier, opts ...STIXOption) (*Relationship, error) {
	if !IsValidIdentifier(id) || !id.ForTypes(TypeAttackPattern, TypeInfrastructure, TypeMalware, TypeTool) {
		return nil, ErrInvalidParameter
	}
	return NewRelationship(RelationshipTypeUses, c.ID, id, opts...)
}

// NewIntrusionSet creates a new IntrusionSet object.
func NewIntrusionSet(name string, opts ...STIXOption) (*IntrusionSet, error) {
	if name == "" {
		return nil, ErrPropertyMissing
	}
	base := newSTIXDomainObject(TypeIntrusionSet)
	obj := &IntrusionSet{STIXDomainObject: base, Name: name}

	err := applyOptions(obj, opts)
	return obj, err
}

const (
	// AttackResourceLevelIndividual indicates resources limited to the average
	// individual; Threat Actor acts independently.
	AttackResourceLevelIndividual = "individual"
	// AttackResourceLevelClub indicates members interact on a social and
	// volunteer basis, often with little personal interest in the specific
	// target. An example might be a core group of unrelated activists who
	// regularly exchange tips on a particular blog. Group persists long term.
	AttackResourceLevelClub = "club"
	// AttackResourceLevelContest indicates a short-lived and perhaps anonymous
	// interaction that concludes when the participants have achieved a single
	// goal. For example, people who break into systems just for thrills or
	// prestige may hold a contest to see who can break into a specific target
	// first. It also includes announced "operations" to achieve a specific
	// goal, such as the original "OpIsrael" call for volunteers to disrupt all
	// of Israel's Internet functions for a day.
	AttackResourceLevelContest = "contest"
	// AttackResourceLevelTeam indicates a formally organized group with a
	// leader, typically motivated by a specific goal and organized around that
	// goal. Group persists long term and typically operates within a single
	// geography.
	AttackResourceLevelTeam = "team"
	// AttackResourceLevelOrganization indicates a larger and better resourced
	// than a team; typically, a company or crime syndicate. Usually operates
	// in multiple geographic areas and persists long term.
	AttackResourceLevelOrganization = "organization"
	// AttackResourceLevelGovernment indicates controls public assets and
	// functions within a jurisdiction; very well resourced and persists long
	// term.
	AttackResourceLevelGovernment = "government"
)

const (
	// AttackMotivationAccidental indicates non-hostile actor whose
	// benevolent or harmless intent inadvertently causes harm.
	AttackMotivationAccidental = "accidental"
	// AttackMotivationCoercion indicates being forced to act on someone else's
	// behalf.
	AttackMotivationCoercion = "coercion"
	// AttackMotivationDominance indicates a desire to assert superiority over
	// someone or something else.
	AttackMotivationDominance = "dominance"
	// AttackMotivationIdeology indicates a passion to express a set of ideas,
	// beliefs, and values that may shape and drive harmful and illegal acts.
	AttackMotivationIdeology = "ideology"
	// AttackMotivationNotoriety indicates seeking prestige or to become well
	// known through some activity.
	AttackMotivationNotoriety = "notoriety"
	// AttackMotivationOrganizationalGain indicates seeking advantage over a
	// competing organization, including a military organization.
	AttackMotivationOrganizationalGain = "organizational-gain"
	// AttackMotivationPersonalGain indicates the desire to improve one’s own
	// financial status.
	AttackMotivationPersonalGain = "personal-gain"
	// AttackMotivationPersonalSatisfaction indicates a desire to satisfy a
	// strictly personal goal, including curiosity, thrill-seeking, amusement,
	// etc.
	AttackMotivationPersonalSatisfaction = "personal-satisfaction"
	// AttackMotivationRevenge indicates a desire to avenge perceived wrongs
	// through harmful actions such as sabotage, violence, theft, fraud, or
	// embarrassing certain individuals or the organization.
	AttackMotivationRevenge = "revenge"
	// AttackMotivationUnpredictable indicates acting without identifiable
	// reason or purpose and creating unpredictable events.
	AttackMotivationUnpredictable = "unpredictable"
)
