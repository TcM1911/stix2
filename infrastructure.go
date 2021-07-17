// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

// Infrastructure SDO represents a type of TTP and describes any systems,
// software services and any associated physical or virtual resources intended
// to support some purpose (e.g., C2 servers used as part of an attack, device
// or server that are part of defence, database servers targeted by an attack,
// etc.). While elements of an attack can be represented by other SDOs or SCOs,
// the Infrastructure SDO represents a named group of related data that
// constitutes the infrastructure.
type Infrastructure struct {
	STIXDomainObject
	// Name is the name or characterizing text used to identify the
	// Infrastructure.
	Name string `json:"name"`
	// Description provides more details and context about the Infrastructure,
	// potentially including its purpose, how it is being used, how it relates
	// to other intelligence activities captured in related objects, and its
	// key characteristics.
	Description string `json:"description,omitempty"`
	// Types is the type of infrastructure being described.
	Types []string `json:"infrastructure_types,omitempty"`
	// Aliases are alternative names used to identify this Infrastructure.
	Aliases []string `json:"aliases,omitempty"`
	// KillChainPhase is a list of Kill Chain Phases for which this
	// Infrastructure is used.
	KillChainPhase []*KillChainPhase `json:"kill_chain_phases,omitempty"`
	// FirstSeen is the time that this Infrastructure was first seen performing
	// malicious activities.
	FirstSeen *Timestamp `json:"first_seen,omitempty"`
	// LastSeen is the time that this Infrastructure was last seen performing
	// malicious activities.
	LastSeen *Timestamp `json:"last_seen,omitempty"`
}

func (o *Infrastructure) MarshalJSON() ([]byte, error) {
	return marshalToJSONHelper(o)
}

// AddConsistsOf documents the objects that are used to make up an
// infrastructure instance, such as ipv4-addr, ipv6-addr, domain-name, url. An
// infrastructure instance consists of zero or more objects.
func (c *Infrastructure) AddConsistsOf(id Identifier, opts ...STIXOption) (*Relationship, error) {
	// According to the specification, "All STIX Cyber-observable Objects" are
	// valid for this reference. "While not all SCO types will make sense as
	// infrastructure, allowing any type of SCO prevents artificially
	// restricting what could be used." Since it's not possible to check for all
	// SCO types and also support custom objects, this check will only check for
	// a valid identifier.
	if !IsValidIdentifier(id) {
		return nil, ErrInvalidParameter
	}
	return NewRelationship(RelationshipTypeConsistsOf, c.ID, id, opts...)
}

// AddControls describes that this infrastructure controls some other
// infrastructure or a malware instance (or family).
func (c *Infrastructure) AddControls(id Identifier, opts ...STIXOption) (*Relationship, error) {
	if !IsValidIdentifier(id) || !id.ForTypes(TypeInfrastructure, TypeMalware) {
		return nil, ErrInvalidParameter
	}
	return NewRelationship(RelationshipTypeControls, c.ID, id, opts...)
}

// AddCommunicatesWith documents that this infrastructure instance communicates
// with the defined network addressable resource.
func (c *Infrastructure) AddCommunicatesWith(id Identifier, opts ...STIXOption) (*Relationship, error) {
	if !IsValidIdentifier(id) || !id.ForTypes(TypeInfrastructure, TypeIPv4Addr, TypeIPv6Addr, TypeDomainName, TypeURL) {
		return nil, ErrInvalidParameter
	}
	return NewRelationship(RelationshipTypeCommunicatesWith, c.ID, id, opts...)
}

// AddDelivers describes that this infrastructure controls some other
// infrastructure or a malware instance (or family).
func (c *Infrastructure) AddDelivers(id Identifier, opts ...STIXOption) (*Relationship, error) {
	if !IsValidIdentifier(id) || !id.ForType(TypeMalware) {
		return nil, ErrInvalidParameter
	}
	return NewRelationship(RelationshipTypeDelivers, c.ID, id, opts...)
}

// AddHas describes that this specific Infrastructure has this specific
// Vulnerability.
func (c *Infrastructure) AddHas(id Identifier, opts ...STIXOption) (*Relationship, error) {
	if !IsValidIdentifier(id) || !id.ForType(TypeVulnerability) {
		return nil, ErrInvalidParameter
	}
	return NewRelationship(RelationshipTypeHas, c.ID, id, opts...)
}

// AddHosts describes that this infrastructure has a tool running on it or is
// used to passively host the tool / malware.
func (c *Infrastructure) AddHosts(id Identifier, opts ...STIXOption) (*Relationship, error) {
	if !IsValidIdentifier(id) || !id.ForTypes(TypeMalware, TypeTool) {
		return nil, ErrInvalidParameter
	}
	return NewRelationship(RelationshipTypeHosts, c.ID, id, opts...)
}

// AddLocatedAt describes that the infrastructure originates from the related
// location.
func (c *Infrastructure) AddLocatedAt(id Identifier, opts ...STIXOption) (*Relationship, error) {
	if !IsValidIdentifier(id) || !id.ForType(TypeLocation) {
		return nil, ErrInvalidParameter
	}
	return NewRelationship(RelationshipTypeLocatedAt, c.ID, id, opts...)
}

// AddUses describes that this infrastructure uses this other infrastructure to
// achieve its objectives.
func (c *Infrastructure) AddUses(id Identifier, opts ...STIXOption) (*Relationship, error) {
	if !IsValidIdentifier(id) || !id.ForType(TypeInfrastructure) {
		return nil, ErrInvalidParameter
	}
	return NewRelationship(RelationshipTypeUses, c.ID, id, opts...)
}

// NewInfrastructure creates a new Infrastructure object.
func NewInfrastructure(name string, opts ...STIXOption) (*Infrastructure, error) {
	if name == "" {
		return nil, ErrPropertyMissing
	}
	base := newSTIXDomainObject(TypeInfrastructure)
	obj := &Infrastructure{STIXDomainObject: base, Name: name}

	err := applyOptions(obj, opts)
	return obj, err
}

const (
	// InfrastructureTypeAmplification specifies infrastructure used for
	// conducting amplification attacks.
	InfrastructureTypeAmplification = "amplification"
	// InfrastructureTypeAnonymization specific infrastructure used for
	// anonymization, such as a proxy.
	InfrastructureTypeAnonymization = "anonymization"
	// InfrastructureTypeBotnet specifies the membership/makeup of a botnet, in
	// terms of the network addresses of the hosts that comprise the botnet.
	InfrastructureTypeBotnet = "botnet"
	// InfrastructureTypeCommandAndControl specifies infrastructure used for
	// command and control (C2). This is typically a domain name or IP address.
	InfrastructureTypeCommandAndControl = "command-and-control"
	// InfrastructureTypeExfiltration specifies infrastructure used as an
	// endpoint for data exfiltration.
	InfrastructureTypeExfiltration = "exfiltration"
	// InfrastructureTypeHostingMalware specifies infrastructure used for
	// hosting malware.
	InfrastructureTypeHostingMalware = "hosting-malware"
	// InfrastructureTypeHostingTargetLists specifies infrastructure used for
	// hosting a list of targets for DDOS attacks, phishing, and other
	// malicious activities. This is typically a domain name or IP address.
	InfrastructureTypeHostingTargetLists = "hosting-target-lists"
	// InfrastructureTypePhishing specifies infrastructure used for conducting
	// phishing attacks.
	InfrastructureTypePhishing = "phishing"
	// InfrastructureTypeReconnaissance specifies infrastructure used for
	// conducting reconnaissance activities.
	InfrastructureTypeReconnaissance = "reconnaissance"
	// InfrastructureTypeStaging specifies infrastructure used for staging.
	InfrastructureTypeStaging = "staging"
	// InfrastructureTypeUndefined specifies an infrastructure of some
	// undefined type.
	InfrastructureTypeUndefined = "undefined"
)
