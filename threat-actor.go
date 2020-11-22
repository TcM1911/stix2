// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

// ThreatActor is an actual individuals, groups, or organizations believed to
// be operating with malicious intent. A ThreatActor is not an IntrusionSet
// but may support or be affiliated with various IntrusionSets, groups, or
// organizations over time.
//
// Threat actors leverage their resources, and possibly the resources of an
// IntrusionSet, to conduct attacks and run Campaigns against targets.
//
// Threat actors can be characterized by their motives, capabilities, goals,
// sophistication level, past activities, resources they have access to, and
// their role in the organization.
type ThreatActor struct {
	STIXDomainObject
	// Name is used to identify this Threat Actor or Threat Actor group.
	Name string `json:"name"`
	// Description provides more details and context about the Threat Actor,
	// potentially including its purpose and its key characteristics.
	Description string `json:"description,omitempty"`
	// Types specifies the type(s) of this threat actor.
	Types []string `json:"threat_actor_types"`
	// Aliases is a list of other names that this Threat Actor is believed to
	// use.
	Aliases []string `json:"aliases,omitempty"`
	// FirstSeen is the time that this Threat Actor was first seen.
	FirstSeen *Timestamp `json:"first_seen,omitempty"`
	// LastSeen is the time that this Threat Actor was last seen.
	LastSeen *Timestamp `json:"last_seen,omitempty"`
	// Roles is a list of roles the ThreatActor plays.
	Roles []string `json:"roles,omitempty"`
	// Goals are high-level goals of this ThreatActor, namely, what are they
	// trying to do. For example, they may be motivated by personal gain, but
	// their goal is to steal credit card numbers. To do this, they may execute
	// specific Campaigns that have detailed objectives like compromising point
	// of sale systems at a large retailer.
	Goals []string `json:"goals,omitempty"`
	// Sophistication is the skill, specific knowledge, special training, or
	// expertise a Threat Actor must have to perform the attack.
	Sophistication string `json:"sophistication,omitempty"`
	// ResourceLevel defines the organizational level at which this Threat
	// Actor typically works, which in turn determines the resources available
	// to this Threat Actor for use in an attack. This attribute is linked to
	// the sophistication property — a specific resource level implies that the
	// Threat Actor has access to at least a specific sophistication level.
	ResourceLevel string `json:"resource_level,omitempty"`
	// PrimaryMotivation is the primary reason, motivation, or purpose behind
	// this Threat Actor. The motivation is why the Threat Actor wishes to
	// achieve the goal (what they are trying to achieve).
	PrimaryMotivation string `json:"primary_motivation,omitempty"`
	// SecondaryMotivations are the secondary reasons, motivations, or purposes
	// behind this ThreatActor. These motivations can exist as an equal or
	// near-equal cause to the primary motivation. However, it does not replace
	// or necessarily magnify the primary motivation, but it might indicate
	// additional context. The position in the list has no significance.
	SecondaryMotivations []string `json:"secondary_motivations,omitempty"`
	// PersonalMotivations are the personal reasons, motivations, or purposes
	// of the ThreatActor regardless of organizational goals. Personal
	// motivation, which is independent of the organization’s goals, describes
	// what impels an individual to carry out an attack. Personal motivation
	// may align with the organization’s motivation—as is common with
	// activists—but more often it supports personal goals. For example, an
	// individual analyst may join a Data Miner corporation because his or her
	// skills may align with the corporation’s objectives. But the analyst most
	// likely performs his or her daily work toward those objectives for
	// personal reward in the form of a paycheck. The motivation of personal
	// reward may be even stronger for Threat Actors who commit illegal acts,
	// as it is more difficult for someone to cross that line purely for
	// altruistic reasons. The position in the list has no significance.
	PersonalMotivations []string `json:"personal_motivations,omitempty"`
}

// AddAttributedTo creates a relationship to the ThreatActor's real identity.
func (a *ThreatActor) AddAttributedTo(id Identifier, opts ...STIXOption) (*Relationship, error) {
	if !IsValidIdentifier(id) || !id.ForType(TypeIdentity) {
		return nil, ErrInvalidParameter
	}
	return NewRelationship(RelationshipTypeAttrubutedTo, a.ID, id, opts...)
}

// AddCompromises creates a relationship that describes that the Threat Actor
// compromises the related Infrastructure.
func (a *ThreatActor) AddCompromises(id Identifier, opts ...STIXOption) (*Relationship, error) {
	if !IsValidIdentifier(id) || !id.ForType(TypeInfrastructure) {
		return nil, ErrInvalidParameter
	}
	return NewRelationship(RelationshipTypeCompromises, a.ID, id, opts...)
}

// AddHosts creates a relationship that describes that the Threat Actor hosts
// the related Infrastructure (e.g. an actor that rents botnets to other threat
// actors).
func (a *ThreatActor) AddHosts(id Identifier, opts ...STIXOption) (*Relationship, error) {
	if !IsValidIdentifier(id) || !id.ForType(TypeInfrastructure) {
		return nil, ErrInvalidParameter
	}
	return NewRelationship(RelationshipTypeHosts, a.ID, id, opts...)
}

// AddOwns creates a relationship that describes that the Threat Actor owns
// the related Infrastructure (e.g. an actor that rents botnets to other threat
// actors).
func (a *ThreatActor) AddOwns(id Identifier, opts ...STIXOption) (*Relationship, error) {
	if !IsValidIdentifier(id) || !id.ForType(TypeInfrastructure) {
		return nil, ErrInvalidParameter
	}
	return NewRelationship(RelationshipTypeOwns, a.ID, id, opts...)
}

// AddImpersonates creates a relationship that describes that the Threat Actor
// impersonates the related Identity.
func (a *ThreatActor) AddImpersonates(id Identifier, opts ...STIXOption) (*Relationship, error) {
	if !IsValidIdentifier(id) || !id.ForType(TypeIdentity) {
		return nil, ErrInvalidParameter
	}
	return NewRelationship(RelationshipTypeImpersonates, a.ID, id, opts...)
}

// AddLocatedAt creates a relationship that describes that the Threat Actor is
// located at or in the related Location.
func (a *ThreatActor) AddLocatedAt(id Identifier, opts ...STIXOption) (*Relationship, error) {
	if !IsValidIdentifier(id) || !id.ForType(TypeLocation) {
		return nil, ErrInvalidParameter
	}
	return NewRelationship(RelationshipTypeLocatedAt, a.ID, id, opts...)
}

// AddTargets creates a relationship that describes that the Threat Actor uses
// exploits of the related Vulnerability or targets the type of victims
// described by the related Identity or Location.
func (a *ThreatActor) AddTargets(id Identifier, opts ...STIXOption) (*Relationship, error) {
	if !IsValidIdentifier(id) || !id.ForTypes(TypeIdentity, TypeLocation, TypeVulnerability) {
		return nil, ErrInvalidParameter
	}
	return NewRelationship(RelationshipTypeTargets, a.ID, id, opts...)
}

// AddUses creates a relationship that describes that attacks carried out as
// part of the Threat Actor typically use the related Attack Pattern,
// Infrastructure,  Malware, or Tool.
func (a *ThreatActor) AddUses(id Identifier, opts ...STIXOption) (*Relationship, error) {
	if !IsValidIdentifier(id) || !id.ForTypes(TypeAttackPattern, TypeInfrastructure, TypeMalware, TypeTool) {
		return nil, ErrInvalidParameter
	}
	return NewRelationship(RelationshipTypeUses, a.ID, id, opts...)
}

// NewThreatActor creates a new ThreatActor object.
func NewThreatActor(name string, opts ...STIXOption) (*ThreatActor, error) {
	if name == "" {
		return nil, ErrPropertyMissing
	}
	base := newSTIXDomainObject(TypeThreatActor)
	obj := &ThreatActor{
		STIXDomainObject: base,
		Name:             name,
	}

	err := applyOptions(obj, opts)
	return obj, err
}

const (
	// ThreatActorTypeActivist are highly motivated, potentially destructive
	// supporter of a social or political cause (e.g., trade, labor,
	// environment, etc.) that attempts to disrupt an organization's business
	// model or damage their image. This category includes actors sometimes
	// referred to as anarchists, cyber vandals, extremists, and hacktivists.
	ThreatActorTypeActivist = "activist"
	// ThreatActorTypeCompetitor is an organization that competes in the same
	// economic marketplace. The goal of a competitor is to gain an advantage
	// in business with respect to the rival organization it targets. It
	// usually does this by copying intellectual property, trade secrets,
	// acquisition strategies, or other technical or business data from a rival
	// organization with the intention of using the data to bolster its own
	// assets and market position.
	ThreatActorTypeCompetitor = "competitor"
	// ThreatActorTypeCrimeSyndicate is an enterprise organized to conduct
	// significant, large-scale criminal activity for profit. Crime syndicates,
	// also known as organized crime, are generally large, well-resourced
	// groups that operate to create profit from all types of crime.
	ThreatActorTypeCrimeSyndicate = "crime-syndicate"
	// ThreatActorTypeCriminal is an individual who commits computer crimes,
	// often for personal financial gain and often involves the theft of
	// something valuable. Intellectual property theft, extortion via
	// ransomware, and physical destruction are common examples. A criminal as
	// defined here refers to those acting individually or in very small or
	// informal groups. For sophisticated organized criminal activity, see the
	// crime syndicate descriptor.
	ThreatActorTypeCriminal = "criminal"
	// ThreatActorTypeHacker is an individual that tends to break into networks
	// for the thrill or the challenge of doing so. Hackers may use advanced
	// skills or simple attack scripts they have downloaded.
	ThreatActorTypeHacker = "hacker"
	// ThreatActorTypeInsiderAccidental is a non-hostile insider who
	// unintentionally exposes the organization to harm. “Insider” in this
	// context includes any person extended internal trust, such as regular
	// employees, contractors, consultants, and temporary workers.
	ThreatActorTypeInsiderAccidental = "insider-accidental"
	// ThreatActorTypeInsiderDisgruntled is a current or former insiders who
	// seek revengeful and harmful retaliation for perceived wrongs. “Insider”
	// in this context includes any person extended internal trust, such as
	// regular employees, contractors, consultants, and temporary workers.
	// Disgruntled threat actors may have extensive knowledge that can be
	// leveraged when conducting attacks and can take any number of actions
	// including sabotage, violence, theft, fraud, espionage, or embarrassing
	// individuals or the organization.
	ThreatActorTypeInsiderDisgruntled = "insider-disgruntled"
	// ThreatActorTypeNationState are entities who work for the government or
	// military of a nation state or who work at their direction. These actors
	// typically have access to significant support, resources, training, and
	// tools and are capable of designing and executing very sophisticated and
	// effective Intrusion Sets and Campaigns.
	ThreatActorTypeNationState = "nation-state"
	// ThreatActorTypeSensationalist seeks to cause embarrassment and brand
	// damage by exposing sensitive information in a manner designed to cause a
	// public relations crisis. A sensationalist may be an individual or small
	// group of people motivated primarily by a need for notoriety. Unlike the
	// activist, the sensationalist generally has no political goal, and is not
	// using bad PR to influence the target to change its behavior or business
	// practices.
	ThreatActorTypeSensationalist = "sensationalist"
	// ThreatActorTypeSpy secretly collects sensitive information for use,
	// dissemination, or sale. Traditional spies (governmental and industrial)
	// are part of a well-resourced intelligence organization and are capable
	// of very sophisticated clandestine operations. However, insiders such as
	// employees or consultants acting as spies can be just as effective and
	// damaging, even when their activities are largely opportunistic and not
	// part of an overall campaign.
	ThreatActorTypeSpy = "spy"
	// ThreatActorTypeTerrorist uses extreme violence to advance a social or
	// political agenda as well as monetary crimes to support its activities.
	// In this context a terrorist refers to individuals who target
	// noncombatants with violence to send a message of fear far beyond the
	// actual events. They may act independently or as part of a terrorist
	// organization. Terrorist organizations must typically raise much of their
	// operating budget through criminal activity, which often occurs online.
	// Terrorists are also often adept at using and covertly manipulating
	// social media for both recruitment and impact.
	ThreatActorTypeTerrorist = "terrorist"
	// ThreatActorTypeUnknown is used if there is not enough information
	// available to determine the type of threat actor.
	ThreatActorTypeUnknown = "unknown"
)

const (
	// ThreatActorRoleAgent executes attacks either on behalf of themselves or
	// at the direction of someone else.
	ThreatActorRoleAgent = "agent"
	// ThreatActorRoleDirector directs the activities, goals, and objectives of
	// the malicious activities.
	ThreatActorRoleDirector = "director"
	// ThreatActorRoleIndependent s a threat actor acting by themselves.
	ThreatActorRoleIndependent = "independent"
	// ThreatActorRoleInfrastructureArchitect is someone who designs the battle
	// space.
	ThreatActorRoleInfrastructureArchitect = "infrastructure-architect"
	// ThreatActorRoleInfrastructureOperator provides and supports the attack
	// infrastructure that is used to deliver the attack (botnet providers,
	// cloud services, etc.).
	ThreatActorRoleInfrastructureOperator = "infrastructure-operator"
	// ThreatActorRoleMalwareAuthor authors malware or other malicious tools.
	ThreatActorRoleMalwareAuthor = "malware-author"
	// ThreatActorRoleSponsor funds the malicious activities.
	ThreatActorRoleSponsor = "sponsor"
)

const (
	// ThreatActorSophisticationNone can carry out random acts of disruption or
	// destruction by running tools they do not understand. Actors in this
	// category have average computer skills.
	//
	// Example Roles: Average User
	//
	// These actors:
	//		* can not launch targeted attacks
	ThreatActorSophisticationNone = "none"
	// ThreatActorSophisticationMinimal can minimally use existing and
	// frequently well known and easy-to-find techniques and programs or
	// scripts to search for and exploit weaknesses in other computers.
	// Commonly referred to as a script-kiddie.
	//
	// These actors rely on others to develop the malicious tools, delivery
	// mechanisms, and execution strategy and often do not fully understand the
	// tool they are using or how they work. They also lack the ability to
	// conduct their own reconnaissance and targeting research.
	//
	// Example Roles: Script-Kiddie
	//
	// These actors:
	//		* attack known weaknesses;
	//		* use well known scripts and tools; and
	//		* have minimal knowledge of the tools.
	ThreatActorSophisticationMinimal = "minimal"
	// ThreatActorSophisticationIntermediate can proficiently use existing
	// attack frameworks and toolkits to search for and exploit vulnerabilities
	// in computers or systems. Actors in this category have computer skills
	// equivalent to an IT professional and typically have a working knowledge
	// of networks, operating systems, and possibly even defensive techniques
	// and will typically exhibit some operational security.
	//
	// These actors rely others to develop the malicious tools and delivery
	// mechanisms but are able to plan their own execution strategy. They are
	// proficient in the tools they are using and how they work and can even
	// make minimal modifications as needed.
	//
	// Example Roles: Toolkit User
	//
	// These actors:
	//		* attack known vulnerabilities;
	//		* use attack frameworks and toolkits; and
	//		* have proficient knowledge of the tools.
	ThreatActorSophisticationIntermediate = "intermediate"
	// ThreatActorSophisticationAdvanced can develop their own tools or scripts
	// from publicly known vulnerabilities to target systems and users. Actors
	// in this category are very adept at IT systems and have a background in
	// software development along with a solid understanding of defensive
	// techniques and operational security.
	//
	// These actors rely on others to find and identify weaknesses and
	// vulnerabilities in systems, but are able to create their own tools,
	// delivery mechanisms, and execution strategies.
	//
	// Example Roles: Toolkit Developer
	//
	// These actors:
	//		* attack known vulnerabilities;
	//		* can create their own tools; and
	//		* have proficient knowledge of the tools.
	ThreatActorSophisticationAdvanced = "advanced"
	// ThreatActorSophisticationExpert can focus on the discovery and use of
	// unknown malicious code, are is adept at installing user and kernel mode
	// rootkits, frequently use data mining tools, target corporate executives
	// and key users (government and industry) for the purpose of stealing
	// personal and corporate data. Actors in this category are very adept at
	// IT systems and software development and are experts with security
	// systems, defensive techniques, attack methods, and operational security.
	//
	// Example Roles: Vulnerability Researcher, Reverse Engineer, Threat
	// Researcher, Malware Creator
	//
	// These actors:
	//		* attack unknown and known vulnerabilities;
	//		* can create  their own tools from scratch; and
	//		* have proficient knowledge of the tools.
	ThreatActorSophisticationExpert = "expert"
	// ThreatActorSophisticationInnovator typically, criminal or state actors who
	// are organized, highly technical, proficient, well-funded professionals
	// working in teams to discover new vulnerabilities and develop exploits.
	//
	// Demonstrates sophisticated capability. An innovator has the ability to
	// create and script unique programs and codes targeting virtually any form
	// of technology. At this level, this actor has a deep knowledge of
	// networks, operating systems, programming languages, firmware, and
	// infrastructure topologies and will demonstrate operational security when
	// conducting his activities. Innovators are largely responsible for the
	// discovery of 0-day vulnerabilities and the development of new attack
	// techniques.
	//
	// Example Roles: Toolkit Innovator, 0-Day Exploit Author
	//
	// These actors:
	//		* attack unknown and known vulnerabilities;
	//		* create attacks against 0-Day exploits from scratch; and
	//		* create new and innovative attacks and toolkits.
	ThreatActorSophisticationInnovator = "innovator"
	// ThreatActorSophisticationStrategic is a state actors who create
	// vulnerabilities through an active program to “influence” commercial
	// products and services during design, development or manufacturing, or
	// with the ability to impact products while in the supply chain to enable
	// exploitation of networks and systems of interest.
	//
	// These actors:
	//		* can create or use entire supply chains to launch an attack;
	//		* can create and design attacks for any systems, software package,
	//		  or device; and
	//		* are responsible for APT-level attacks.
	ThreatActorSophisticationStrategic = "strategic"
)
