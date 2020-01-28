// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

// AttackPattern is a type of TTP that describe ways that adversaries
// attempt to compromise targets. Attack Patterns are used to help categorize
// attacks, generalize specific attacks to the patterns that they follow, and
// provide detailed information about how attacks are performed. An example of
// an attack pattern is "spear phishing": a common type of attack where an
// attacker sends a carefully crafted e-mail message to a party with the intent
// of getting them to click a link or open an attachment to deliver malware.
// Attack Patterns can also be more specific; spear phishing as practiced by a
// particular threat actor (e.g., they might generally say that the target won
// a contest) can also be an Attack Pattern. The Attack Pattern SDO contains
// textual descriptions of the pattern along with references to
// externally-defined taxonomies of attacks such as CAPEC.
type AttackPattern struct {
	STIXDomainObject
	// Name is used to identify the Attack Pattern.
	Name string `json:"name"`
	// Description provides more details and context about the Attack Pattern,
	// potentially including its purpose and its key characteristics.
	Description string `json:"description,omitempty"`
	// Aliases are alternative names used to identify this Attack Pattern.
	Aliases []string `json:"aliases,omitempty"`
	// KillChainPhase is a list of Kill Chain Phases for which this Attack
	// Pattern is used.
	KillChainPhase []*KillChainPhase `json:"kill_chain_phases,omitempty"`
}

// AddDelivers creates a relationship to a malware delivered by this object.
func (a *AttackPattern) AddDelivers(id Identifier, opts ...RelationshipOption) (*Relationship, error) {
	if !IsValidIdentifier(id) || !id.ForType(TypeMalware) {
		return nil, ErrInvalidParameter
	}
	return NewRelationship(RelationshipTypeDelivers, a.ID, id, opts...)
}

// AddTargets creates a relationship to either an identity, location, or
// vulnerability that is targeted by this attack pattern.
func (a *AttackPattern) AddTargets(id Identifier, opts ...RelationshipOption) (*Relationship, error) {
	if !IsValidIdentifier(id) || (!id.ForType(TypeLocation) &&
		!id.ForType(TypeIdentity)) && !id.ForType(TypeVulnerability) {
		return nil, ErrInvalidParameter
	}
	return NewRelationship(RelationshipTypeTargets, a.ID, id, opts...)
}

// AddUses creates a relationship to either a malware or tool that is used by
// the attack pattern.
func (a *AttackPattern) AddUses(id Identifier, opts ...RelationshipOption) (*Relationship, error) {
	if !IsValidIdentifier(id) || (!id.ForType(TypeMalware) && !id.ForType(TypeTool)) {
		return nil, ErrInvalidParameter
	}
	return NewRelationship(RelationshipTypeTargets, a.ID, id, opts...)
}

// NewAttackPattern creates a new AttackPattern object.
func NewAttackPattern(name string, opts ...AttackPatternOption) (*AttackPattern, error) {
	if name == "" {
		return nil, ErrPropertyMissing
	}
	base := newSTIXDomainObject(TypeAttackPattern)
	obj := &AttackPattern{STIXDomainObject: base, Name: name}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(obj)
	}

	return obj, nil
}

// AttackPatternOption is an optional parameter when constructing a
// AttackPattern object.
type AttackPatternOption func(a *AttackPattern)

/*
	Base object options
*/

// AttackPatternOptionSpecVersion sets the STIX spec version.
func AttackPatternOptionSpecVersion(ver string) AttackPatternOption {
	return func(obj *AttackPattern) {
		obj.SpecVersion = ver
	}
}

// AttackPatternOptionExternalReferences sets the external references attribute.
func AttackPatternOptionExternalReferences(refs []*ExternalReference) AttackPatternOption {
	return func(obj *AttackPattern) {
		obj.ExternalReferences = refs
	}
}

// AttackPatternOptionObjectMarking sets the object marking attribute.
func AttackPatternOptionObjectMarking(om []Identifier) AttackPatternOption {
	return func(obj *AttackPattern) {
		obj.ObjectMarking = om
	}
}

// AttackPatternOptionGranularMarking sets the granular marking attribute.
func AttackPatternOptionGranularMarking(gm *GranularMarking) AttackPatternOption {
	return func(obj *AttackPattern) {
		obj.GranularMarking = gm
	}
}

// AttackPatternOptionLang sets the lang attribute.
func AttackPatternOptionLang(lang string) AttackPatternOption {
	return func(obj *AttackPattern) {
		obj.Lang = lang
	}
}

// AttackPatternOptionConfidence sets the confidence attribute.
func AttackPatternOptionConfidence(confidence int) AttackPatternOption {
	return func(obj *AttackPattern) {
		obj.Confidence = confidence
	}
}

// AttackPatternOptionLables sets the lables attribute.
func AttackPatternOptionLables(lables []string) AttackPatternOption {
	return func(obj *AttackPattern) {
		obj.Lables = lables
	}
}

// AttackPatternOptionRevoked sets the revoked attribute.
func AttackPatternOptionRevoked(rev bool) AttackPatternOption {
	return func(obj *AttackPattern) {
		obj.Revoked = rev
	}
}

// AttackPatternOptionModified sets the modified attribute.
func AttackPatternOptionModified(t *Timestamp) AttackPatternOption {
	return func(obj *AttackPattern) {
		obj.Modified = t
	}
}

// AttackPatternOptionCreated sets the created attribute.
func AttackPatternOptionCreated(t *Timestamp) AttackPatternOption {
	return func(obj *AttackPattern) {
		obj.Created = t
	}
}

// AttackPatternOptionCreatedBy sets the created by by attribute.
func AttackPatternOptionCreatedBy(id Identifier) AttackPatternOption {
	return func(obj *AttackPattern) {
		obj.CreatedBy = id
	}
}

/*
	AttackPattern object options
*/

// AttackPatternOptionDesciption sets the description attribute.
func AttackPatternOptionDesciption(des string) AttackPatternOption {
	return func(obj *AttackPattern) {
		obj.Description = des
	}
}

// AttackPatternOptionAliases sets the aliases attribute.
func AttackPatternOptionAliases(a []string) AttackPatternOption {
	return func(obj *AttackPattern) {
		obj.Aliases = a
	}
}

// AttackPatternOptionKillChainPhase sets the kill chain phase attribute.
func AttackPatternOptionKillChainPhase(k []*KillChainPhase) AttackPatternOption {
	return func(obj *AttackPattern) {
		obj.KillChainPhase = k
	}
}
