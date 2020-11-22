// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

// Identity can represent actual individuals, organizations, or groups (e.g.,
// ACME, Inc.) as well as classes of individuals, organizations, systems or
// groups (e.g., the finance sector). The Identity SDO can capture basic
// identifying information, contact information, and the sectors that the
// Identity belongs to. Identity is used in STIX to represent, among other
// things, targets of attacks, information sources, object creators, and threat
// actor identities.
type Identity struct {
	STIXDomainObject
	// Name is the name of this Identity. When referring to a specific entity
	// (e.g., an individual or organization), this property SHOULD contain the
	// canonical name of the specific entity.
	Name string `json:"name"`
	// Description provides more details and context about the Identity,
	// potentially including its purpose and its key characteristics.
	Description string `json:"description,omitempty"`
	// Roles is a list of roles that this Identity performs (e.g., CEO, Domain
	// Administrators, Doctors, Hospital, or Retailer). No open vocabulary is
	// yet defined for this property.
	Roles []string `json:"roles,omitempty"`
	// Class is the type of entity that this Identity describes, e.g.,
	// an individual or organization.
	Class string `json:"identity_class"`
	// Sectors is a list of industry sectors that this Identity belongs to.
	Sectors []string `json:"sectors,omitempty"`
	// ContactInformation is the contact information (e-mail, phone number,
	// etc.) for this Identity. No format for this information is currently
	// defined by this specification.
	ContactInformation string `json:"contact_information,omitempty"`
}

// AddLocatedAt creates a relationship to a location hat the Identity is
// located at or in the related Location.
func (c *Identity) AddLocatedAt(id Identifier, opts ...STIXOption) (*Relationship, error) {
	if !IsValidIdentifier(id) || !id.ForType(TypeLocation) {
		return nil, ErrInvalidParameter
	}
	return NewRelationship(RelationshipTypeLocatedAt, c.ID, id, opts...)
}

// NewIdentity creates a new Identity object.
func NewIdentity(name string, opts ...STIXOption) (*Identity, error) {
	if name == "" {
		return nil, ErrPropertyMissing
	}
	base := newSTIXDomainObject(TypeIdentity)
	obj := &Identity{STIXDomainObject: base, Name: name}

	err := applyOptions(obj, opts)
	return obj, err
}

const (
	// IdentityClassIndividual represents a single person.
	IdentityClassIndividual = "individual"
	// IdentityClassGroup represents an informal collection of people, without
	// formal governance, such as a distributed hacker group.
	IdentityClassGroup = "group"
	// IdentityClassSystem represents a computer system, such as a SIEM.
	IdentityClassSystem = "system"
	// IdentityClassOrganization represents a formal organization of people,
	// with governance, such as a company or country.
	IdentityClassOrganization = "organization"
	// IdentityClassClass represents a class of entities, such as all
	// hospitals, all Europeans, or the Domain Administrators in a system.
	IdentityClassClass = "class"
	// IdentityClassUnspecified represents an unspecified (or unknown) whether
	// the classification is an individual, group, system, organization, or
	// class.
	IdentityClassUnspecified = "unspecified"
)

const (
	// IdentitySectorAgriculture represents the agriculture sector.
	IdentitySectorAgriculture = "agriculture"
	// IdentitySectorAerospace represents the aerospace sector.
	IdentitySectorAerospace = "aerospace"
	// IdentitySectorAutomotive represents the automotive sector.
	IdentitySectorAutomotive = "automotive"
	// IdentitySectorCommunications represents the communications sector.
	IdentitySectorCommunications = "communications"
	// IdentitySectorConstruction represents the construction sector.
	IdentitySectorConstruction = "construction"
	// IdentitySectorDefence represents the defence sector.
	IdentitySectorDefence = "defence"
	// IdentitySectorEducation represents the education sector.
	IdentitySectorEducation = "education"
	// IdentitySectorEnergy represents the energy sector.
	IdentitySectorEnergy = "energy"
	// IdentitySectorEntertainment represents the entertainment sector.
	IdentitySectorEntertainment = "entertainment"
	// IdentitySectorFinancialServices represents the financial service sector.
	IdentitySectorFinancialServices = "financial-services"
	// IdentitySectorGovernmentNational represents the national government.
	IdentitySectorGovernmentNational = "government-national"
	// IdentitySectorGovernmentRegional represents the regional government.
	IdentitySectorGovernmentRegional = "government-regional"
	// IdentitySectorGovernmentLocal represents the local government.
	IdentitySectorGovernmentLocal = "government-local"
	// IdentitySectorGovernmentPublicServices represents the public services.
	IdentitySectorGovernmentPublicServices = "government-public-services"
	// IdentitySectorHealthcare represents the healthcare sector.
	IdentitySectorHealthcare = "healthcare"
	// IdentitySectorHospitalityLeisure represents the hospitality sector.
	IdentitySectorHospitalityLeisure = "hospitality-leisure"
	// IdentitySectorInfrastructure represents the infrastructure sector.
	IdentitySectorInfrastructure = "infrastructure"
	// IdentitySectorInsurance represents the insurance sector.
	IdentitySectorInsurance = "insurance"
	// IdentitySectorManufacturing represents the manufacturing sector.
	IdentitySectorManufacturing = "manufacturing"
	// IdentitySectorMining represents the mining sector.
	IdentitySectorMining = "mining"
	// IdentitySectorNonProfit represents the non-profit sector.
	IdentitySectorNonProfit = "non-profit"
	// IdentitySectorPharmaceuticals represents the pharmaceuticals sector.
	IdentitySectorPharmaceuticals = "pharmaceuticals"
	// IdentitySectorRetail represents the retail sector.
	IdentitySectorRetail = "retail"
	// IdentitySectorTechnology represents the technology sector.
	IdentitySectorTechnology = "technology"
	// IdentitySectorTelecommunications represents the telecommunications sector.
	IdentitySectorTelecommunications = "telecommunications"
	//IdentitySectorTransportation represents the transportation sector.
	IdentitySectorTransportation = "transportation"
	// IdentitySectorUtilities represents the utilities sector.
	IdentitySectorUtilities = "utilities"
)
