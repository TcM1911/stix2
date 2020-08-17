// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

// Tool is a legitimate software that can be used by threat actors to perform
// attacks. Knowing how and when threat actors use such tools can be important
// for understanding how campaigns are executed. Unlike malware, these tools or
// software packages are often found on a system and have legitimate purposes
// for power users, system administrators, network administrators, or even
// normal users. Remote access tools (e.g., RDP) and network scanning tools
// (e.g., Nmap) are examples of Tools that may be used by a Threat Actor during
// an attack.
//
// The Tool SDO characterizes the properties of these software tools and can be
// used as a basis for making an assertion about how a Threat Actor uses them
// during an attack. It contains properties to name and describe the tool, a
// list of Kill Chain Phases the tool can be used to carry out, and the version
// of the tool.
//
// This SDO MUST NOT be used to characterize malware. Further, Tool MUST NOT be
// used to characterise tools used as part of a course of action in response to
// an attack.
type Tool struct {
	STIXDomainObject
	// Name is used to identify the Tool.
	Name string `json:"name"`
	// Description provides more details and context about the Tool,
	// potentially including its purpose and its key characteristics.
	Description string `json:"description,omitempty"`
	// Types is the kind(s) of tool(s) being described.
	Types []string `json:"tool_types"`
	// Aliases are alternative names used to identify this Tool.
	Aliases []string `json:"aliases,omitempty"`
	// KillChainPhase is the list of kill chain phases for which this Tool can
	// be used.
	KillChainPhase []*KillChainPhase `json:"kill_chain_phases,omitempty"`
	// ToolVersion is the version identifier associated with the Tool.
	ToolVersion string `json:"tool_version,omitempty"`
}

// AddDelivers creates a relationship that describes that this Tool is used to
// deliver a malware instance (or family).
func (a *Tool) AddDelivers(id Identifier, opts ...RelationshipOption) (*Relationship, error) {
	if !IsValidIdentifier(id) || !id.ForType(TypeMalware) {
		return nil, ErrInvalidParameter
	}
	return NewRelationship(RelationshipTypeDelivers, a.ID, id, opts...)
}

// AddDrops creates a relationship that documents that this Tool drops a
// malware instance (or family).
func (a *Tool) AddDrops(id Identifier, opts ...RelationshipOption) (*Relationship, error) {
	if !IsValidIdentifier(id) || !id.ForType(TypeMalware) {
		return nil, ErrInvalidParameter
	}
	return NewRelationship(RelationshipTypeDrops, a.ID, id, opts...)
}

// AddHas creates a relationship that describes that this specific Tool has
// this specific Vulnerability.
func (a *Tool) AddHas(id Identifier, opts ...RelationshipOption) (*Relationship, error) {
	if !IsValidIdentifier(id) || !id.ForType(TypeVulnerability) {
		return nil, ErrInvalidParameter
	}
	return NewRelationship(RelationshipTypeHas, a.ID, id, opts...)
}

// AddTargets creates a relationship that documents that this Tool is being
// used to target this Identity, Infrastructure, Location, or exploit the
// Vulnerability.
func (a *Tool) AddTargets(id Identifier, opts ...RelationshipOption) (*Relationship, error) {
	if !IsValidIdentifier(id) || !id.ForTypes(TypeIdentity, TypeInfrastructure, TypeLocation, TypeVulnerability) {
		return nil, ErrInvalidParameter
	}
	return NewRelationship(RelationshipTypeTargets, a.ID, id, opts...)
}

// AddUses creates a relationship that describes that this Tool uses the
// related Infrastructure.
func (a *Tool) AddUses(id Identifier, opts ...RelationshipOption) (*Relationship, error) {
	if !IsValidIdentifier(id) || !id.ForType(TypeInfrastructure) {
		return nil, ErrInvalidParameter
	}
	return NewRelationship(RelationshipTypeUses, a.ID, id, opts...)
}

// NewTool creates a new Tool object.
func NewTool(name string, opts ...ToolOption) (*Tool, error) {
	if name == "" {
		return nil, ErrPropertyMissing
	}
	base := newSTIXDomainObject(TypeTool)
	obj := &Tool{
		STIXDomainObject: base,
		Name:             name,
	}

	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(obj)
	}
	return obj, nil
}

// ToolOption is an optional parameter when constructing a
// Tool object.
type ToolOption func(a *Tool)

/*
	Base object options
*/

// ToolOptionSpecVersion sets the STIX spec version.
func ToolOptionSpecVersion(ver string) ToolOption {
	return func(obj *Tool) {
		obj.SpecVersion = ver
	}
}

// ToolOptionExternalReferences sets the external references attribute.
func ToolOptionExternalReferences(refs []*ExternalReference) ToolOption {
	return func(obj *Tool) {
		obj.ExternalReferences = refs
	}
}

// ToolOptionObjectMarking sets the object marking attribute.
func ToolOptionObjectMarking(om []Identifier) ToolOption {
	return func(obj *Tool) {
		obj.ObjectMarking = om
	}
}

// ToolOptionGranularMarking sets the granular marking attribute.
func ToolOptionGranularMarking(gm []*GranularMarking) ToolOption {
	return func(obj *Tool) {
		obj.GranularMarking = gm
	}
}

// ToolOptionLang sets the lang attribute.
func ToolOptionLang(lang string) ToolOption {
	return func(obj *Tool) {
		obj.Lang = lang
	}
}

// ToolOptionConfidence sets the confidence attribute.
func ToolOptionConfidence(confidence int) ToolOption {
	return func(obj *Tool) {
		obj.Confidence = confidence
	}
}

// ToolOptionLabels sets the labels attribute.
func ToolOptionLabels(labels []string) ToolOption {
	return func(obj *Tool) {
		obj.Labels = labels
	}
}

// ToolOptionRevoked sets the revoked attribute.
func ToolOptionRevoked(rev bool) ToolOption {
	return func(obj *Tool) {
		obj.Revoked = rev
	}
}

// ToolOptionModified sets the modified attribute.
func ToolOptionModified(t *Timestamp) ToolOption {
	return func(obj *Tool) {
		obj.Modified = t
	}
}

// ToolOptionCreated sets the created attribute.
func ToolOptionCreated(t *Timestamp) ToolOption {
	return func(obj *Tool) {
		obj.Created = t
	}
}

// ToolOptionCreatedBy sets the created by by attribute.
func ToolOptionCreatedBy(id Identifier) ToolOption {
	return func(obj *Tool) {
		obj.CreatedBy = id
	}
}

/*
	Tool object options
*/

// ToolOptionDescription sets the description attribute.
func ToolOptionDescription(s string) ToolOption {
	return func(obj *Tool) {
		obj.Description = s
	}
}

// ToolOptionTypes sets the tool types attribute.
func ToolOptionTypes(s []string) ToolOption {
	return func(obj *Tool) {
		obj.Types = s
	}
}

// ToolOptionAliases sets the aliases attribute.
func ToolOptionAliases(s []string) ToolOption {
	return func(obj *Tool) {
		obj.Aliases = s
	}
}

// ToolOptionKillChainPhase sets the kill chain phase attribute.
func ToolOptionKillChainPhase(s []*KillChainPhase) ToolOption {
	return func(obj *Tool) {
		obj.KillChainPhase = s
	}
}

// ToolOptionToolVersion sets the tool version attribute.
func ToolOptionToolVersion(s string) ToolOption {
	return func(obj *Tool) {
		obj.ToolVersion = s
	}
}

const (
	// ToolTypeDenialOfService is used to perform denial of service attacks or
	// DDoS attacks, such as Low Orbit Ion Cannon (LOIC) and DHCPig.
	ToolTypeDenialOfService = "denial-of-service"
	// ToolTypeExploitation is used to exploit software and systems, such as
	// sqlmap and Metasploit.
	ToolTypeExploitation = "exploitation"
	// ToolTypeInformationGathering is used to enumerate system and network
	// information, e.g., NMAP.
	ToolTypeInformationGathering = "information-gathering"
	// ToolTypeNetworkCapture is used to capture network traffic, such as
	// Wireshark and Kismet
	ToolTypeNetworkCapture = "network-capture"
	// ToolTypeCredentialExploitation is used to crack password databases or
	// otherwise exploit/discover credentials, either locally or remotely, such
	// as John the Ripper and NCrack.
	ToolTypeCredentialExploitation = "credential-exploitation"
	// ToolTypeRemoteAccess is used to access machines remotely, such as VNC
	// and Remote Desktop.
	ToolTypeRemoteAccess = "remote-access"
	// ToolTypeVulnerabilityScanning is used to scan systems and networks for
	// vulnerabilities, e.g., Nessus.
	ToolTypeVulnerabilityScanning = "vulnerability-scanning"
	// ToolTypeUnknown if there is not enough information available to
	// determine the type of tool.
	ToolTypeUnknown = "unknown"
)
