// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import (
	"encoding/json"
	"fmt"
)

// StixCollection is a collection of STIX objects.
type StixCollection struct {
	ASs                map[Identifier]*AS
	Artifacts          map[Identifier]*Artifact
	AttackPatterns     map[Identifier]*AttackPattern
	Campaigns          map[Identifier]*Campaign
	CourseOfActions    map[Identifier]*CourseOfAction
	Directories        map[Identifier]*Directory
	DomainNames        map[Identifier]*Domain
	EmailAddresses     map[Identifier]*EmailAddress
	EmailMessages      map[Identifier]*EmailMessage
	Files              map[Identifier]*File
	Groups             map[Identifier]*Grouping
	IPv4Addresses      map[Identifier]*IPv4Address
	IPv6Addresses      map[Identifier]*IPv6Address
	Identities         map[Identifier]*Identity
	Indicators         map[Identifier]*Indicator
	Infrastructures    map[Identifier]*Infrastructure
	IntrusionSets      map[Identifier]*IntrusionSet
	LanguageContents   map[Identifier]*LanguageContent
	Locations          map[Identifier]*Location
	MACs               map[Identifier]*MACAddress
	Malware            map[Identifier]*Malware
	MalwareAnalysis    map[Identifier]*MalwareAnalysis
	MarkingDefinitions map[Identifier]*MarkingDefinition
	Mutexes            map[Identifier]*Mutex
	NetworkTraffic     map[Identifier]*NetworkTraffic
	Notes              map[Identifier]*Note
	ObservedData       map[Identifier]*ObservedData
	Opinions           map[Identifier]*Opinion
	Processes          map[Identifier]*Process
	RegistryKeys       map[Identifier]*RegistryKey
	Relationships      map[Identifier]*Relationship
	Reports            map[Identifier]*Report
	Sightings          map[Identifier]*Sighting
	Software           map[Identifier]*Software
	ThreatActors       map[Identifier]*ThreatActor
	Tools              map[Identifier]*Tool
	URLs               map[Identifier]*URL
	UserAccounts       map[Identifier]*UserAccount
	Vulnerabilities    map[Identifier]*Vulnerability
	X509Certificates   map[Identifier]*X509Certificate
}

// FromJSON parses JSON data and returns a StixCollection with the extracted
// objects.
func FromJSON(data []byte) (*StixCollection, error) {
	collection := &StixCollection{}

	// First assume it is a STIX bundle.
	var bundle Bundle
	if err := json.Unmarshal(data, &bundle); err == nil {
		err = processBundle(collection, bundle)
		if err != nil {
			return nil, err
		}
		return collection, nil
	}

	// If it is not a bundle, assume it is an array of JSON objects.
	var a []json.RawMessage
	if err := json.Unmarshal(data, &a); err == nil {
		err = processObjects(collection, a)
		if err != nil {
			return nil, err
		}
		return collection, nil
	}

	// Unknown format.
	return nil, fmt.Errorf("unknown JSON format")
}

func processBundle(collection *StixCollection, bundle Bundle) error {
	return processObjects(collection, bundle.Objects)
}

func processObjects(collection *StixCollection, objects []json.RawMessage) error {
	var peak peakObject
	var err error
	for _, data := range objects {
		err = json.Unmarshal(data, &peak)
		if err != nil {
			return err
		}
		switch peak.Type {
		case TypeAS:
			err = parseAS(data, collection)
			if err != nil {
				return fmt.Errorf("failed to parse an AS object: %w", err)
			}
		case TypeArtifact:
			err = parseArtifact(data, collection)
			if err != nil {
				return fmt.Errorf("failed to parse an artifact object: %w", err)
			}
		case TypeAttackPattern:
			err = parseAttackPattern(data, collection)
			if err != nil {
				return fmt.Errorf("failed to parse an attack-pattern object: %w", err)
			}
		case TypeCampaign:
			err = parseCampaign(data, collection)
			if err != nil {
				return fmt.Errorf("failed to parse a campaign object: %w", err)
			}
		case TypeCourseOfAction:
			err = parseCourseOfAction(data, collection)
			if err != nil {
				return fmt.Errorf("failed to parse a course-of-action object: %w", err)
			}
		case TypeDirectory:
			err = parseDirector(data, collection)
			if err != nil {
				return fmt.Errorf("failed to parse a directory object: %w", err)
			}
		case TypeDomainName:
			err = parseDomainName(data, collection)
			if err != nil {
				return fmt.Errorf("failed to parse a domain name object: %w", err)
			}
		case TypeEmailAddress:
			err = parseEmailAddress(data, collection)
			if err != nil {
				return fmt.Errorf("failed to parse an email address object: %w", err)
			}
		case TypeEmailMessage:
			err = parseEmailMessage(data, collection)
			if err != nil {
				return fmt.Errorf("failed to parse an email message object: %w", err)
			}
		case TypeFile:
			err = parseFile(data, collection)
			if err != nil {
				return fmt.Errorf("failed to parse a file object: %w", err)
			}
		case TypeGrouping:
			err = parseGrouping(data, collection)
			if err != nil {
				return fmt.Errorf("failed to parse a grouping object: %w", err)
			}
		case TypeIPv4Addr:
			err = parseIPv4(data, collection)
			if err != nil {
				return fmt.Errorf("failed to parse an IPv4 object: %w", err)
			}
		case TypeIPv6Addr:
			err = parseIPv6(data, collection)
			if err != nil {
				return fmt.Errorf("failed to parse an IPv6 object: %w", err)
			}
		case TypeIdentity:
			err = parseIdentity(data, collection)
			if err != nil {
				return fmt.Errorf("failed to parse an identity object: %w", err)
			}
		case TypeIndicator:
			err = parseIndicator(data, collection)
			if err != nil {
				return fmt.Errorf("failed to parse an indicator object: %w", err)
			}
		case TypeInfrastructure:
			err = parseInfrastructure(data, collection)
			if err != nil {
				return fmt.Errorf("failed to parse an infrastructure object: %w", err)
			}
		case TypeIntrusionSet:
			err = parseIntrusionSet(data, collection)
			if err != nil {
				return fmt.Errorf("failed to parse an intrusion-set object: %w", err)
			}
		case TypeLanguageContent:
			err = parseLanguageContent(data, collection)
			if err != nil {
				return fmt.Errorf("failed to parse a language content object: %w", err)
			}
		case TypeLocation:
			err = parseLocation(data, collection)
			if err != nil {
				return fmt.Errorf("failed to parse a location object: %w", err)
			}
		case TypeMACAddress:
			err = parseMAC(data, collection)
			if err != nil {
				return fmt.Errorf("failed to parse a MAC object: %w", err)
			}
		case TypeMalware:
			err = parseMalware(data, collection)
			if err != nil {
				return fmt.Errorf("failed to parse a malware object: %w", err)
			}
		case TypeMalwareAnalysis:
			err = parseMalwareAnalysis(data, collection)
			if err != nil {
				return fmt.Errorf("failed to parse a malware analysis object: %w", err)
			}
		case TypeMarkingDefinition:
			err = parseMarkingDefinition(data, collection)
			if err != nil {
				return fmt.Errorf("failed to parse a marking definition object: %w", err)
			}
		case TypeMutex:
			err = parseMutex(data, collection)
			if err != nil {
				return fmt.Errorf("failed to parse a mutex object: %w", err)
			}
		case TypeNetworkTraffic:
			err = parseNetworkTraffic(data, collection)
			if err != nil {
				return fmt.Errorf("failed to parse a network traffic object: %w", err)
			}
		case TypeNote:
			err = parseNote(data, collection)
			if err != nil {
				return fmt.Errorf("failed to parse a note object: %w", err)
			}
		case TypeObservedData:
			err = parseObservedData(data, collection)
			if err != nil {
				return fmt.Errorf("failed to parse an observed data object: %w", err)
			}
		case TypeOpinion:
			err = parseOpinion(data, collection)
			if err != nil {
				return fmt.Errorf("failed to parse an opinion object: %w", err)
			}
		case TypeProcess:
			err = parseProcess(data, collection)
			if err != nil {
				return fmt.Errorf("failed to parse a process object: %w", err)
			}
		case TypeRegistryKey:
			err = parseRegistryKey(data, collection)
			if err != nil {
				return fmt.Errorf("failed to parse a registry key object: %w", err)
			}
		case TypeRelationship:
			err = parseRelationship(data, collection)
			if err != nil {
				return fmt.Errorf("failed to parse a relationship object: %w", err)
			}
		case TypeReport:
			err = parseReport(data, collection)
			if err != nil {
				return fmt.Errorf("failed to parse a report object: %w", err)
			}
		case TypeSighting:
			err = parseSighting(data, collection)
			if err != nil {
				return fmt.Errorf("failed to parse a sighting object: %w", err)
			}
		case TypeSoftware:
			err = parseSoftware(data, collection)
			if err != nil {
				return fmt.Errorf("failed to parse a software object: %w", err)
			}
		case TypeThreatActor:
			err = parseThreatActor(data, collection)
			if err != nil {
				return fmt.Errorf("failed to parse a threat actor object: %w", err)
			}
		case TypeTool:
			err = parseTool(data, collection)
			if err != nil {
				return fmt.Errorf("failed to parse a tool object: %w", err)
			}
		case TypeURL:
			err = parseURL(data, collection)
			if err != nil {
				return fmt.Errorf("failed to parse a URL object: %w", err)
			}
		case TypeUserAccount:
			err = parseUseAccount(data, collection)
			if err != nil {
				return fmt.Errorf("failed to parse a user account object: %w", err)
			}
		case TypeVulnerability:
			err = parseVulnerability(data, collection)
			if err != nil {
				return fmt.Errorf("failed to parse a vulnerability object: %w", err)
			}
		case TypeX509Certificate:
			err = parseX509(data, collection)
			if err != nil {
				return fmt.Errorf("failed to parse a x509 certificate object: %w", err)
			}
		}
	}
	return nil
}

func parseAS(data []byte, collection *StixCollection) error {
	if collection.ASs == nil {
		collection.ASs = make(map[Identifier]*AS)
	}
	var as AS
	err := json.Unmarshal(data, &as)
	if err != nil {
		return err
	}
	collection.ASs[as.ID] = &as
	return nil
}

func parseArtifact(data []byte, collection *StixCollection) error {
	if collection.Artifacts == nil {
		collection.Artifacts = make(map[Identifier]*Artifact)
	}
	var v Artifact
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.Artifacts[v.ID] = &v
	return nil
}

func parseAttackPattern(data []byte, collection *StixCollection) error {
	if collection.AttackPatterns == nil {
		collection.AttackPatterns = make(map[Identifier]*AttackPattern)
	}
	var v AttackPattern
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.AttackPatterns[v.ID] = &v
	return nil
}

func parseCampaign(data []byte, collection *StixCollection) error {
	if collection.Campaigns == nil {
		collection.Campaigns = make(map[Identifier]*Campaign)
	}
	var v Campaign
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.Campaigns[v.ID] = &v
	return nil
}

func parseCourseOfAction(data []byte, collection *StixCollection) error {
	if collection.CourseOfActions == nil {
		collection.CourseOfActions = make(map[Identifier]*CourseOfAction)
	}
	var v CourseOfAction
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.CourseOfActions[v.ID] = &v
	return nil
}

func parseDirector(data []byte, collection *StixCollection) error {
	if collection.Directories == nil {
		collection.Directories = make(map[Identifier]*Directory)
	}
	var v Directory
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.Directories[v.ID] = &v
	return nil
}

func parseDomainName(data []byte, collection *StixCollection) error {
	if collection.DomainNames == nil {
		collection.DomainNames = make(map[Identifier]*Domain)
	}
	var v Domain
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.DomainNames[v.ID] = &v
	return nil
}

func parseEmailAddress(data []byte, collection *StixCollection) error {
	if collection.EmailAddresses == nil {
		collection.EmailAddresses = make(map[Identifier]*EmailAddress)
	}
	var v EmailAddress
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.EmailAddresses[v.ID] = &v
	return nil
}

func parseEmailMessage(data []byte, collection *StixCollection) error {
	if collection.EmailMessages == nil {
		collection.EmailMessages = make(map[Identifier]*EmailMessage)
	}
	var v EmailMessage
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.EmailMessages[v.ID] = &v
	return nil
}

func parseFile(data []byte, collection *StixCollection) error {
	if collection.Files == nil {
		collection.Files = make(map[Identifier]*File)
	}
	var v File
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.Files[v.ID] = &v
	return nil
}

func parseGrouping(data []byte, collection *StixCollection) error {
	if collection.Groups == nil {
		collection.Groups = make(map[Identifier]*Grouping)
	}
	var v Grouping
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.Groups[v.ID] = &v
	return nil
}

func parseIPv4(data []byte, collection *StixCollection) error {
	if collection.IPv4Addresses == nil {
		collection.IPv4Addresses = make(map[Identifier]*IPv4Address)
	}
	var v IPv4Address
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.IPv4Addresses[v.ID] = &v
	return nil
}

func parseIPv6(data []byte, collection *StixCollection) error {
	if collection.IPv6Addresses == nil {
		collection.IPv6Addresses = make(map[Identifier]*IPv6Address)
	}
	var v IPv6Address
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.IPv6Addresses[v.ID] = &v
	return nil
}

func parseIdentity(data []byte, collection *StixCollection) error {
	if collection.Identities == nil {
		collection.Identities = make(map[Identifier]*Identity)
	}
	var v Identity
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.Identities[v.ID] = &v
	return nil
}

func parseIndicator(data []byte, collection *StixCollection) error {
	if collection.Indicators == nil {
		collection.Indicators = make(map[Identifier]*Indicator)
	}
	var v Indicator
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.Indicators[v.ID] = &v
	return nil
}

func parseInfrastructure(data []byte, collection *StixCollection) error {
	if collection.Infrastructures == nil {
		collection.Infrastructures = make(map[Identifier]*Infrastructure)
	}
	var v Infrastructure
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.Infrastructures[v.ID] = &v
	return nil
}

func parseIntrusionSet(data []byte, collection *StixCollection) error {
	if collection.IntrusionSets == nil {
		collection.IntrusionSets = make(map[Identifier]*IntrusionSet)
	}
	var v IntrusionSet
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.IntrusionSets[v.ID] = &v
	return nil
}

func parseLanguageContent(data []byte, collection *StixCollection) error {
	if collection.LanguageContents == nil {
		collection.LanguageContents = make(map[Identifier]*LanguageContent)
	}
	var v LanguageContent
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.LanguageContents[v.ID] = &v
	return nil
}

func parseLocation(data []byte, collection *StixCollection) error {
	if collection.Locations == nil {
		collection.Locations = make(map[Identifier]*Location)
	}
	var v Location
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.Locations[v.ID] = &v
	return nil
}

func parseMAC(data []byte, collection *StixCollection) error {
	if collection.MACs == nil {
		collection.MACs = make(map[Identifier]*MACAddress)
	}
	var v MACAddress
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.MACs[v.ID] = &v
	return nil
}

func parseMalware(data []byte, collection *StixCollection) error {
	if collection.Malware == nil {
		collection.Malware = make(map[Identifier]*Malware)
	}
	var v Malware
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.Malware[v.ID] = &v
	return nil
}

func parseMalwareAnalysis(data []byte, collection *StixCollection) error {
	if collection.MalwareAnalysis == nil {
		collection.MalwareAnalysis = make(map[Identifier]*MalwareAnalysis)
	}
	var v MalwareAnalysis
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.MalwareAnalysis[v.ID] = &v
	return nil
}

func parseMarkingDefinition(data []byte, collection *StixCollection) error {
	if collection.MarkingDefinitions == nil {
		collection.MarkingDefinitions = make(map[Identifier]*MarkingDefinition)
	}
	var v MarkingDefinition
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.MarkingDefinitions[v.ID] = &v
	return nil
}

func parseMutex(data []byte, collection *StixCollection) error {
	if collection.Mutexes == nil {
		collection.Mutexes = make(map[Identifier]*Mutex)
	}
	var v Mutex
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.Mutexes[v.ID] = &v
	return nil
}

func parseNetworkTraffic(data []byte, collection *StixCollection) error {
	if collection.NetworkTraffic == nil {
		collection.NetworkTraffic = make(map[Identifier]*NetworkTraffic)
	}
	var v NetworkTraffic
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.NetworkTraffic[v.ID] = &v
	return nil
}

func parseNote(data []byte, collection *StixCollection) error {
	if collection.Notes == nil {
		collection.Notes = make(map[Identifier]*Note)
	}
	var v Note
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.Notes[v.ID] = &v
	return nil
}

func parseObservedData(data []byte, collection *StixCollection) error {
	if collection.ObservedData == nil {
		collection.ObservedData = make(map[Identifier]*ObservedData)
	}
	var v ObservedData
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.ObservedData[v.ID] = &v
	return nil
}

func parseOpinion(data []byte, collection *StixCollection) error {
	if collection.Opinions == nil {
		collection.Opinions = make(map[Identifier]*Opinion)
	}
	var v Opinion
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.Opinions[v.ID] = &v
	return nil
}

func parseProcess(data []byte, collection *StixCollection) error {
	if collection.Processes == nil {
		collection.Processes = make(map[Identifier]*Process)
	}
	var v Process
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.Processes[v.ID] = &v
	return nil
}

func parseRegistryKey(data []byte, collection *StixCollection) error {
	if collection.RegistryKeys == nil {
		collection.RegistryKeys = make(map[Identifier]*RegistryKey)
	}
	var v RegistryKey
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.RegistryKeys[v.ID] = &v
	return nil
}

func parseRelationship(data []byte, collection *StixCollection) error {
	if collection.Relationships == nil {
		collection.Relationships = make(map[Identifier]*Relationship)
	}
	var v Relationship
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.Relationships[v.ID] = &v
	return nil
}

func parseReport(data []byte, collection *StixCollection) error {
	if collection.Reports == nil {
		collection.Reports = make(map[Identifier]*Report)
	}
	var v Report
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.Reports[v.ID] = &v
	return nil
}

func parseSighting(data []byte, collection *StixCollection) error {
	if collection.Sightings == nil {
		collection.Sightings = make(map[Identifier]*Sighting)
	}
	var v Sighting
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.Sightings[v.ID] = &v
	return nil
}

func parseSoftware(data []byte, collection *StixCollection) error {
	if collection.Software == nil {
		collection.Software = make(map[Identifier]*Software)
	}
	var v Software
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.Software[v.ID] = &v
	return nil
}

func parseThreatActor(data []byte, collection *StixCollection) error {
	if collection.ThreatActors == nil {
		collection.ThreatActors = make(map[Identifier]*ThreatActor)
	}
	var v ThreatActor
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.ThreatActors[v.ID] = &v
	return nil
}

func parseTool(data []byte, collection *StixCollection) error {
	if collection.Tools == nil {
		collection.Tools = make(map[Identifier]*Tool)
	}
	var v Tool
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.Tools[v.ID] = &v
	return nil
}

func parseURL(data []byte, collection *StixCollection) error {
	if collection.URLs == nil {
		collection.URLs = make(map[Identifier]*URL)
	}
	var v URL
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.URLs[v.ID] = &v
	return nil
}

func parseUseAccount(data []byte, collection *StixCollection) error {
	if collection.UserAccounts == nil {
		collection.UserAccounts = make(map[Identifier]*UserAccount)
	}
	var v UserAccount
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.UserAccounts[v.ID] = &v
	return nil
}

func parseVulnerability(data []byte, collection *StixCollection) error {
	if collection.Vulnerabilities == nil {
		collection.Vulnerabilities = make(map[Identifier]*Vulnerability)
	}
	var v Vulnerability
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.Vulnerabilities[v.ID] = &v
	return nil
}

func parseX509(data []byte, collection *StixCollection) error {
	if collection.X509Certificates == nil {
		collection.X509Certificates = make(map[Identifier]*X509Certificate)
	}
	var v X509Certificate
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.X509Certificates[v.ID] = &v
	return nil
}

type peakObject struct {
	Type StixType `json:"type"`
}
