// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import (
	"encoding/json"
	"fmt"
	"sync"
)

// StixObject is a generic representation of a STIX object.
type StixObject interface {
	// GetID returns the identifier for the object.
	GetID() Identifier
	// GetType returns the object's type.
	GetType() StixType
}

// StixCollection is a collection of STIX objects.
type StixCollection struct {
	objects map[StixType]map[Identifier]interface{}
	objinit sync.Once
}

// Add adds or updates an object in the collection.
func (c *StixCollection) Add(obj StixObject) {
	c.objinit.Do(func() {
		objectInit(c)
	})
	bucket := c.objects[obj.GetType()]
	bucket[obj.GetID()] = obj
}

// AllObjects returns a slice of all StixObjects that are in the collection.
func (c *StixCollection) AllObjects() []StixObject {
	// Calculate the size of the array.
	size := 0
	for _, ar := range c.objects {
		size = size + len(ar)
	}

	result := make([]StixObject, 0, size)
	for _, v := range c.objects {
		for _, vv := range v {
			result = append(result, vv.(StixObject))
		}
	}
	return result
}

// ToBundle returns a STIX bundle with all the StixObjects in the
// StixCollection.
func (c *StixCollection) ToBundle() (*Bundle, error) {
	return NewBundle(c.AllObjects()...)
}

// AS returns the AS with the identifier id.
func (c *StixCollection) AS(id Identifier) *AS {
	obj := c.getObject(TypeAS, id)
	if obj == nil {
		return nil
	}
	return obj.(*AS)
}

// ASs returns all the AS in the collection.
func (c *StixCollection) ASs() []*AS {
	data := make([]*AS, 0, len(c.objects[TypeAS]))
	for _, v := range c.objects[TypeAS] {
		data = append(data, v.(*AS))
	}
	return data
}

// Artifact returns the Artifact with the identifier id.
func (c *StixCollection) Artifact(id Identifier) *Artifact {
	obj := c.getObject(TypeArtifact, id)
	if obj == nil {
		return nil
	}
	return obj.(*Artifact)
}

// Artifacts returns all the Artifacts in the collection.
func (c *StixCollection) Artifacts() []*Artifact {
	data := make([]*Artifact, 0, len(c.objects[TypeArtifact]))
	for _, v := range c.objects[TypeArtifact] {
		data = append(data, v.(*Artifact))
	}
	return data
}

// AttackPattern returns the AttackPattern with the identifier id.
func (c *StixCollection) AttackPattern(id Identifier) *AttackPattern {
	obj := c.getObject(TypeAttackPattern, id)
	if obj == nil {
		return nil
	}
	return obj.(*AttackPattern)
}

// AttackPatterns returns all the AttackPatterns in the collection.
func (c *StixCollection) AttackPatterns() []*AttackPattern {
	data := make([]*AttackPattern, 0, len(c.objects[TypeAttackPattern]))
	for _, v := range c.objects[TypeAttackPattern] {
		data = append(data, v.(*AttackPattern))
	}
	return data
}

// Campaign returns the Campaign with the identifier id.
func (c *StixCollection) Campaign(id Identifier) *Campaign {
	obj := c.getObject(TypeCampaign, id)
	if obj == nil {
		return nil
	}
	return obj.(*Campaign)
}

// Campaigns returns all the Campaigns in the collection.
func (c *StixCollection) Campaigns() []*Campaign {
	data := make([]*Campaign, 0, len(c.objects[TypeCampaign]))
	for _, v := range c.objects[TypeCampaign] {
		data = append(data, v.(*Campaign))
	}
	return data
}

// CourseOfAction returns the CourseOfAction with the identifier id.
func (c *StixCollection) CourseOfAction(id Identifier) *CourseOfAction {
	obj := c.getObject(TypeCourseOfAction, id)
	if obj == nil {
		return nil
	}
	return obj.(*CourseOfAction)
}

// CourseOfActions returns all the CourseOfActions in the collection.
func (c *StixCollection) CourseOfActions() []*CourseOfAction {
	data := make([]*CourseOfAction, 0, len(c.objects[TypeCourseOfAction]))
	for _, v := range c.objects[TypeCourseOfAction] {
		data = append(data, v.(*CourseOfAction))
	}
	return data
}

// Directory returns the Directory with the identifier id.
func (c *StixCollection) Directory(id Identifier) *Directory {
	obj := c.getObject(TypeDirectory, id)
	if obj == nil {
		return nil
	}
	return obj.(*Directory)
}

// Directories returns all the Directories in the collection.
func (c *StixCollection) Directories() []*Directory {
	data := make([]*Directory, 0, len(c.objects[TypeDirectory]))
	for _, v := range c.objects[TypeDirectory] {
		data = append(data, v.(*Directory))
	}
	return data
}

// DomainName returns the DomainName with the identifier id.
func (c *StixCollection) DomainName(id Identifier) *DomainName {
	obj := c.getObject(TypeDomainName, id)
	if obj == nil {
		return nil
	}
	return obj.(*DomainName)
}

// DomainNames returns all the DomainNames in the collection.
func (c *StixCollection) DomainNames() []*DomainName {
	data := make([]*DomainName, 0, len(c.objects[TypeDomainName]))
	for _, v := range c.objects[TypeDomainName] {
		data = append(data, v.(*DomainName))
	}
	return data
}

// EmailAddress returns the EmailAddress with the identifier id.
func (c *StixCollection) EmailAddress(id Identifier) *EmailAddress {
	obj := c.getObject(TypeEmailAddress, id)
	if obj == nil {
		return nil
	}
	return obj.(*EmailAddress)
}

// EmailAddresses returns all the EmailAddresses in the collection.
func (c *StixCollection) EmailAddresses() []*EmailAddress {
	data := make([]*EmailAddress, 0, len(c.objects[TypeEmailAddress]))
	for _, v := range c.objects[TypeEmailAddress] {
		data = append(data, v.(*EmailAddress))
	}
	return data
}

// EmailMessage returns the EmailMessage with the identifier id.
func (c *StixCollection) EmailMessage(id Identifier) *EmailMessage {
	obj := c.getObject(TypeEmailMessage, id)
	if obj == nil {
		return nil
	}
	return obj.(*EmailMessage)
}

// EmailMessages returns all the EmailMessages in the collection.
func (c *StixCollection) EmailMessages() []*EmailMessage {
	data := make([]*EmailMessage, 0, len(c.objects[TypeEmailMessage]))
	for _, v := range c.objects[TypeEmailMessage] {
		data = append(data, v.(*EmailMessage))
	}
	return data
}

// File returns the File with the identifier id.
func (c *StixCollection) File(id Identifier) *File {
	obj := c.getObject(TypeFile, id)
	if obj == nil {
		return nil
	}
	return obj.(*File)
}

// Files returns all the Files in the collection.
func (c *StixCollection) Files() []*File {
	data := make([]*File, 0, len(c.objects[TypeFile]))
	for _, v := range c.objects[TypeFile] {
		data = append(data, v.(*File))
	}
	return data
}

// Group returns the Group with the identifier id.
func (c *StixCollection) Group(id Identifier) *Grouping {
	obj := c.getObject(TypeGrouping, id)
	if obj == nil {
		return nil
	}
	return obj.(*Grouping)
}

// Groups returns all the Groups in the collection.
func (c *StixCollection) Groups() []*Grouping {
	data := make([]*Grouping, 0, len(c.objects[TypeGrouping]))
	for _, v := range c.objects[TypeGrouping] {
		data = append(data, v.(*Grouping))
	}
	return data
}

// IPv4Address returns the IPv4Address with the identifier id.
func (c *StixCollection) IPv4Address(id Identifier) *IPv4Address {
	obj := c.getObject(TypeIPv4Addr, id)
	if obj == nil {
		return nil
	}
	return obj.(*IPv4Address)
}

// IPv4Addresses returns all the IPv4Addresses in the collection.
func (c *StixCollection) IPv4Addresses() []*IPv4Address {
	data := make([]*IPv4Address, 0, len(c.objects[TypeIPv4Addr]))
	for _, v := range c.objects[TypeIPv4Addr] {
		data = append(data, v.(*IPv4Address))
	}
	return data
}

// IPv6Address returns the IPv6Address with the identifier id.
func (c *StixCollection) IPv6Address(id Identifier) *IPv6Address {
	obj := c.getObject(TypeIPv6Addr, id)
	if obj == nil {
		return nil
	}
	return obj.(*IPv6Address)
}

// IPv6Addresses returns all the IPv6Addresses in the collection.
func (c *StixCollection) IPv6Addresses() []*IPv6Address {
	data := make([]*IPv6Address, 0, len(c.objects[TypeIPv6Addr]))
	for _, v := range c.objects[TypeIPv6Addr] {
		data = append(data, v.(*IPv6Address))
	}
	return data
}

// Identity returns the Identity with the identifier id.
func (c *StixCollection) Identity(id Identifier) *Identity {
	obj := c.getObject(TypeIdentity, id)
	if obj == nil {
		return nil
	}
	return obj.(*Identity)
}

// Identities returns all the Identities in the collection.
func (c *StixCollection) Identities() []*Identity {
	data := make([]*Identity, 0, len(c.objects[TypeIdentity]))
	for _, v := range c.objects[TypeIdentity] {
		data = append(data, v.(*Identity))
	}
	return data
}

// Indicator returns the Indicator with the identifier id.
func (c *StixCollection) Indicator(id Identifier) *Indicator {
	obj := c.getObject(TypeIndicator, id)
	if obj == nil {
		return nil
	}
	return obj.(*Indicator)
}

// Indicators returns all the Indicators in the collection.
func (c *StixCollection) Indicators() []*Indicator {
	data := make([]*Indicator, 0, len(c.objects[TypeIndicator]))
	for _, v := range c.objects[TypeIndicator] {
		data = append(data, v.(*Indicator))
	}
	return data
}

// Infrastructure returns the Infrastructure with the identifier id.
func (c *StixCollection) Infrastructure(id Identifier) *Infrastructure {
	obj := c.getObject(TypeInfrastructure, id)
	if obj == nil {
		return nil
	}
	return obj.(*Infrastructure)
}

// Infrastructures returns all the Infrastructures in the collection.
func (c *StixCollection) Infrastructures() []*Infrastructure {
	data := make([]*Infrastructure, 0, len(c.objects[TypeInfrastructure]))
	for _, v := range c.objects[TypeInfrastructure] {
		data = append(data, v.(*Infrastructure))
	}
	return data
}

// IntrusionSet returns the IntrusionSet with the identifier id.
func (c *StixCollection) IntrusionSet(id Identifier) *IntrusionSet {
	obj := c.getObject(TypeIntrusionSet, id)
	if obj == nil {
		return nil
	}
	return obj.(*IntrusionSet)
}

// IntrusionSets returns all the IntrusionSets in the collection.
func (c *StixCollection) IntrusionSets() []*IntrusionSet {
	data := make([]*IntrusionSet, 0, len(c.objects[TypeIntrusionSet]))
	for _, v := range c.objects[TypeIntrusionSet] {
		data = append(data, v.(*IntrusionSet))
	}
	return data
}

// LanguageContent returns the LanguageContent with the identifier id.
func (c *StixCollection) LanguageContent(id Identifier) *LanguageContent {
	obj := c.getObject(TypeLanguageContent, id)
	if obj == nil {
		return nil
	}
	return obj.(*LanguageContent)
}

// LanguageContents returns all the LanguageContents in the collection.
func (c *StixCollection) LanguageContents() []*LanguageContent {
	data := make([]*LanguageContent, 0, len(c.objects[TypeLanguageContent]))
	for _, v := range c.objects[TypeLanguageContent] {
		data = append(data, v.(*LanguageContent))
	}
	return data
}

// Location returns the Location with the identifier id.
func (c *StixCollection) Location(id Identifier) *Location {
	obj := c.getObject(TypeLocation, id)
	if obj == nil {
		return nil
	}
	return obj.(*Location)
}

// Locations returns all the Locations in the collection.
func (c *StixCollection) Locations() []*Location {
	data := make([]*Location, 0, len(c.objects[TypeLocation]))
	for _, v := range c.objects[TypeLocation] {
		data = append(data, v.(*Location))
	}
	return data
}

// MAC returns the MAC with the identifier id.
func (c *StixCollection) MAC(id Identifier) *MACAddress {
	obj := c.getObject(TypeMACAddress, id)
	if obj == nil {
		return nil
	}
	return obj.(*MACAddress)
}

// MACs returns all the MACs in the collection.
func (c *StixCollection) MACs() []*MACAddress {
	data := make([]*MACAddress, 0, len(c.objects[TypeMACAddress]))
	for _, v := range c.objects[TypeMACAddress] {
		data = append(data, v.(*MACAddress))
	}
	return data
}

// Malware returns the Malware with the identifier id.
func (c *StixCollection) Malware(id Identifier) *Malware {
	obj := c.getObject(TypeMalware, id)
	if obj == nil {
		return nil
	}
	return obj.(*Malware)
}

// AllMalware returns all the Malware in the collection.
func (c *StixCollection) AllMalware() []*Malware {
	data := make([]*Malware, 0, len(c.objects[TypeMalware]))
	for _, v := range c.objects[TypeMalware] {
		data = append(data, v.(*Malware))
	}
	return data
}

// MalwareAnalysis returns the MalwareAnalysis with the identifier id.
func (c *StixCollection) MalwareAnalysis(id Identifier) *MalwareAnalysis {
	obj := c.getObject(TypeMalwareAnalysis, id)
	if obj == nil {
		return nil
	}
	return obj.(*MalwareAnalysis)
}

// MalwareAnalyses returns all the MalwareAnalyses in the collection.
func (c *StixCollection) MalwareAnalyses() []*MalwareAnalysis {
	data := make([]*MalwareAnalysis, 0, len(c.objects[TypeMalwareAnalysis]))
	for _, v := range c.objects[TypeMalwareAnalysis] {
		data = append(data, v.(*MalwareAnalysis))
	}
	return data
}

// MarkingDefinition returns the MarkingDefinition with the identifier id.
func (c *StixCollection) MarkingDefinition(id Identifier) *MarkingDefinition {
	obj := c.getObject(TypeMarkingDefinition, id)
	if obj == nil {
		return nil
	}
	return obj.(*MarkingDefinition)
}

// MarkingDefinitions returns all the MarkingDefinitions in the collection.
func (c *StixCollection) MarkingDefinitions() []*MarkingDefinition {
	data := make([]*MarkingDefinition, 0, len(c.objects[TypeMarkingDefinition]))
	for _, v := range c.objects[TypeMarkingDefinition] {
		data = append(data, v.(*MarkingDefinition))
	}
	return data
}

// Mutex returns the Mutex with the identifier id.
func (c *StixCollection) Mutex(id Identifier) *Mutex {
	obj := c.getObject(TypeMutex, id)
	if obj == nil {
		return nil
	}
	return obj.(*Mutex)
}

// Mutexes returns all the Mutexes in the collection.
func (c *StixCollection) Mutexes() []*Mutex {
	data := make([]*Mutex, 0, len(c.objects[TypeMutex]))
	for _, v := range c.objects[TypeMutex] {
		data = append(data, v.(*Mutex))
	}
	return data
}

// NetworkTraffic returns the NetworkTraffic with the identifier id.
func (c *StixCollection) NetworkTraffic(id Identifier) *NetworkTraffic {
	obj := c.getObject(TypeNetworkTraffic, id)
	if obj == nil {
		return nil
	}
	return obj.(*NetworkTraffic)
}

// AllNetworkTraffic returns all the NetworkTraffic in the collection.
func (c *StixCollection) AllNetworkTraffic() []*NetworkTraffic {
	data := make([]*NetworkTraffic, 0, len(c.objects[TypeNetworkTraffic]))
	for _, v := range c.objects[TypeNetworkTraffic] {
		data = append(data, v.(*NetworkTraffic))
	}
	return data
}

// Note returns the Note with the identifier id.
func (c *StixCollection) Note(id Identifier) *Note {
	obj := c.getObject(TypeNote, id)
	if obj == nil {
		return nil
	}
	return obj.(*Note)
}

// Notes returns all the Notes in the collection.
func (c *StixCollection) Notes() []*Note {
	data := make([]*Note, 0, len(c.objects[TypeNote]))
	for _, v := range c.objects[TypeNote] {
		data = append(data, v.(*Note))
	}
	return data
}

// ObservedData returns the ObservedData with the identifier id.
func (c *StixCollection) ObservedData(id Identifier) *ObservedData {
	obj := c.getObject(TypeObservedData, id)
	if obj == nil {
		return nil
	}
	return obj.(*ObservedData)
}

// AllObservedData returns all the ObservedData in the collection.
func (c *StixCollection) AllObservedData() []*ObservedData {
	data := make([]*ObservedData, 0, len(c.objects[TypeObservedData]))
	for _, v := range c.objects[TypeObservedData] {
		data = append(data, v.(*ObservedData))
	}
	return data
}

// Opinion returns the Opinion with the identifier id.
func (c *StixCollection) Opinion(id Identifier) *Opinion {
	obj := c.getObject(TypeOpinion, id)
	if obj == nil {
		return nil
	}
	return obj.(*Opinion)
}

// Opinions returns all the Opinions in the collection.
func (c *StixCollection) Opinions() []*Opinion {
	data := make([]*Opinion, 0, len(c.objects[TypeOpinion]))
	for _, v := range c.objects[TypeOpinion] {
		data = append(data, v.(*Opinion))
	}
	return data
}

// Process returns the Process with the identifier id.
func (c *StixCollection) Process(id Identifier) *Process {
	obj := c.getObject(TypeProcess, id)
	if obj == nil {
		return nil
	}
	return obj.(*Process)
}

// Processes returns all the Processes in the collection.
func (c *StixCollection) Processes() []*Process {
	data := make([]*Process, 0, len(c.objects[TypeProcess]))
	for _, v := range c.objects[TypeProcess] {
		data = append(data, v.(*Process))
	}
	return data
}

// RegistryKey returns the RegistryKey with the identifier id.
func (c *StixCollection) RegistryKey(id Identifier) *RegistryKey {
	obj := c.getObject(TypeRegistryKey, id)
	if obj == nil {
		return nil
	}
	return obj.(*RegistryKey)
}

// RegistryKeys returns all the RegistryKeys in the collection.
func (c *StixCollection) RegistryKeys() []*RegistryKey {
	data := make([]*RegistryKey, 0, len(c.objects[TypeRegistryKey]))
	for _, v := range c.objects[TypeRegistryKey] {
		data = append(data, v.(*RegistryKey))
	}
	return data
}

// Relationship returns the Relationship with the identifier id.
func (c *StixCollection) Relationship(id Identifier) *Relationship {
	obj := c.getObject(TypeRelationship, id)
	if obj == nil {
		return nil
	}
	return obj.(*Relationship)
}

// Relationships returns all the Relationships in the collection.
func (c *StixCollection) Relationships() []*Relationship {
	data := make([]*Relationship, 0, len(c.objects[TypeRelationship]))
	for _, v := range c.objects[TypeRelationship] {
		data = append(data, v.(*Relationship))
	}
	return data
}

// Report returns the Report with the identifier id.
func (c *StixCollection) Report(id Identifier) *Report {
	obj := c.getObject(TypeReport, id)
	if obj == nil {
		return nil
	}
	return obj.(*Report)
}

// Reports returns all the Reports in the collection.
func (c *StixCollection) Reports() []*Report {
	data := make([]*Report, 0, len(c.objects[TypeReport]))
	for _, v := range c.objects[TypeReport] {
		data = append(data, v.(*Report))
	}
	return data
}

// Sighting returns the Sighting with the identifier id.
func (c *StixCollection) Sighting(id Identifier) *Sighting {
	obj := c.getObject(TypeSighting, id)
	if obj == nil {
		return nil
	}
	return obj.(*Sighting)
}

// Sightings returns all the Sightings in the collection.
func (c *StixCollection) Sightings() []*Sighting {
	data := make([]*Sighting, 0, len(c.objects[TypeSighting]))
	for _, v := range c.objects[TypeSighting] {
		data = append(data, v.(*Sighting))
	}
	return data
}

// Software returns the Software with the identifier id.
func (c *StixCollection) Software(id Identifier) *Software {
	obj := c.getObject(TypeSoftware, id)
	if obj == nil {
		return nil
	}
	return obj.(*Software)
}

// AllSoftware returns all the Software in the collection.
func (c *StixCollection) AllSoftware() []*Software {
	data := make([]*Software, 0, len(c.objects[TypeSoftware]))
	for _, v := range c.objects[TypeSoftware] {
		data = append(data, v.(*Software))
	}
	return data
}

// ThreatActor returns the ThreatActor with the identifier id.
func (c *StixCollection) ThreatActor(id Identifier) *ThreatActor {
	obj := c.getObject(TypeThreatActor, id)
	if obj == nil {
		return nil
	}
	return obj.(*ThreatActor)
}

// ThreatActors returns all the ThreatActors in the collection.
func (c *StixCollection) ThreatActors() []*ThreatActor {
	data := make([]*ThreatActor, 0, len(c.objects[TypeThreatActor]))
	for _, v := range c.objects[TypeThreatActor] {
		data = append(data, v.(*ThreatActor))
	}
	return data
}

// Tool returns the Tool with the identifier id.
func (c *StixCollection) Tool(id Identifier) *Tool {
	obj := c.getObject(TypeTool, id)
	if obj == nil {
		return nil
	}
	return obj.(*Tool)
}

// Tools returns all the Tools in the collection.
func (c *StixCollection) Tools() []*Tool {
	data := make([]*Tool, 0, len(c.objects[TypeTool]))
	for _, v := range c.objects[TypeTool] {
		data = append(data, v.(*Tool))
	}
	return data
}

// URL returns the URL with the identifier id.
func (c *StixCollection) URL(id Identifier) *URL {
	obj := c.getObject(TypeURL, id)
	if obj == nil {
		return nil
	}
	return obj.(*URL)
}

// URLs returns all the URLs in the collection.
func (c *StixCollection) URLs() []*URL {
	data := make([]*URL, 0, len(c.objects[TypeURL]))
	for _, v := range c.objects[TypeURL] {
		data = append(data, v.(*URL))
	}
	return data
}

// UserAccount returns the UserAccount with the identifier id.
func (c *StixCollection) UserAccount(id Identifier) *UserAccount {
	obj := c.getObject(TypeUserAccount, id)
	if obj == nil {
		return nil
	}
	return obj.(*UserAccount)
}

// UserAccounts returns all the UserAccounts in the collection.
func (c *StixCollection) UserAccounts() []*UserAccount {
	data := make([]*UserAccount, 0, len(c.objects[TypeUserAccount]))
	for _, v := range c.objects[TypeUserAccount] {
		data = append(data, v.(*UserAccount))
	}
	return data
}

// Vulnerability returns the Vulnerability with the identifier id.
func (c *StixCollection) Vulnerability(id Identifier) *Vulnerability {
	obj := c.getObject(TypeVulnerability, id)
	if obj == nil {
		return nil
	}
	return obj.(*Vulnerability)
}

// Vulnerabilities returns all the Vulnerabilities in the collection.
func (c *StixCollection) Vulnerabilities() []*Vulnerability {
	data := make([]*Vulnerability, 0, len(c.objects[TypeVulnerability]))
	for _, v := range c.objects[TypeVulnerability] {
		data = append(data, v.(*Vulnerability))
	}
	return data
}

// X509Certificate returns the X509Certificate with the identifier id.
func (c *StixCollection) X509Certificate(id Identifier) *X509Certificate {
	obj := c.getObject(TypeX509Certificate, id)
	if obj == nil {
		return nil
	}
	return obj.(*X509Certificate)
}

// X509Certificates returns all the X509Certificates in the collection.
func (c *StixCollection) X509Certificates() []*X509Certificate {
	data := make([]*X509Certificate, 0, len(c.objects[TypeX509Certificate]))
	for _, v := range c.objects[TypeX509Certificate] {
		data = append(data, v.(*X509Certificate))
	}
	return data
}

func (c *StixCollection) getObject(typ StixType, id Identifier) interface{} {
	return c.objects[typ][id]
}

func objectInit(c *StixCollection) {
	c.objects = map[StixType]map[Identifier]interface{}{}
	for _, k := range AllTypes {
		c.objects[k] = map[Identifier]interface{}{}
	}
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
	var as AS
	err := json.Unmarshal(data, &as)
	if err != nil {
		return err
	}
	collection.Add(&as)
	return nil
}

func parseArtifact(data []byte, collection *StixCollection) error {
	var v Artifact
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.Add(&v)
	return nil
}

func parseAttackPattern(data []byte, collection *StixCollection) error {
	var v AttackPattern
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.Add(&v)
	return nil
}

func parseCampaign(data []byte, collection *StixCollection) error {
	var v Campaign
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.Add(&v)
	return nil
}

func parseCourseOfAction(data []byte, collection *StixCollection) error {
	var v CourseOfAction
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.Add(&v)
	return nil
}

func parseDirector(data []byte, collection *StixCollection) error {
	var v Directory
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.Add(&v)
	return nil
}

func parseDomainName(data []byte, collection *StixCollection) error {
	var v DomainName
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.Add(&v)
	return nil
}

func parseEmailAddress(data []byte, collection *StixCollection) error {
	var v EmailAddress
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.Add(&v)
	return nil
}

func parseEmailMessage(data []byte, collection *StixCollection) error {
	var v EmailMessage
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.Add(&v)
	return nil
}

func parseFile(data []byte, collection *StixCollection) error {
	var v File
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.Add(&v)
	return nil
}

func parseGrouping(data []byte, collection *StixCollection) error {
	var v Grouping
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.Add(&v)
	return nil
}

func parseIPv4(data []byte, collection *StixCollection) error {
	var v IPv4Address
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.Add(&v)
	return nil
}

func parseIPv6(data []byte, collection *StixCollection) error {
	var v IPv6Address
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.Add(&v)
	return nil
}

func parseIdentity(data []byte, collection *StixCollection) error {
	var v Identity
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.Add(&v)
	return nil
}

func parseIndicator(data []byte, collection *StixCollection) error {
	var v Indicator
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.Add(&v)
	return nil
}

func parseInfrastructure(data []byte, collection *StixCollection) error {
	var v Infrastructure
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.Add(&v)
	return nil
}

func parseIntrusionSet(data []byte, collection *StixCollection) error {
	var v IntrusionSet
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.Add(&v)
	return nil
}

func parseLanguageContent(data []byte, collection *StixCollection) error {
	var v LanguageContent
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.Add(&v)
	return nil
}

func parseLocation(data []byte, collection *StixCollection) error {
	var v Location
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.Add(&v)
	return nil
}

func parseMAC(data []byte, collection *StixCollection) error {
	var v MACAddress
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.Add(&v)
	return nil
}

func parseMalware(data []byte, collection *StixCollection) error {
	var v Malware
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.Add(&v)
	return nil
}

func parseMalwareAnalysis(data []byte, collection *StixCollection) error {
	var v MalwareAnalysis
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.Add(&v)
	return nil
}

func parseMarkingDefinition(data []byte, collection *StixCollection) error {
	var v MarkingDefinition
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.Add(&v)
	return nil
}

func parseMutex(data []byte, collection *StixCollection) error {
	var v Mutex
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.Add(&v)
	return nil
}

func parseNetworkTraffic(data []byte, collection *StixCollection) error {
	var v NetworkTraffic
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.Add(&v)
	return nil
}

func parseNote(data []byte, collection *StixCollection) error {
	var v Note
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.Add(&v)
	return nil
}

func parseObservedData(data []byte, collection *StixCollection) error {
	var v ObservedData
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.Add(&v)
	return nil
}

func parseOpinion(data []byte, collection *StixCollection) error {
	var v Opinion
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.Add(&v)
	return nil
}

func parseProcess(data []byte, collection *StixCollection) error {
	var v Process
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.Add(&v)
	return nil
}

func parseRegistryKey(data []byte, collection *StixCollection) error {
	var v RegistryKey
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.Add(&v)
	return nil
}

func parseRelationship(data []byte, collection *StixCollection) error {
	var v Relationship
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.Add(&v)
	return nil
}

func parseReport(data []byte, collection *StixCollection) error {
	var v Report
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.Add(&v)
	return nil
}

func parseSighting(data []byte, collection *StixCollection) error {
	var v Sighting
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.Add(&v)
	return nil
}

func parseSoftware(data []byte, collection *StixCollection) error {
	var v Software
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.Add(&v)
	return nil
}

func parseThreatActor(data []byte, collection *StixCollection) error {
	var v ThreatActor
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.Add(&v)
	return nil
}

func parseTool(data []byte, collection *StixCollection) error {
	var v Tool
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.Add(&v)
	return nil
}

func parseURL(data []byte, collection *StixCollection) error {
	var v URL
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.Add(&v)
	return nil
}

func parseUseAccount(data []byte, collection *StixCollection) error {
	var v UserAccount
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.Add(&v)
	return nil
}

func parseVulnerability(data []byte, collection *StixCollection) error {
	var v Vulnerability
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.Add(&v)
	return nil
}

func parseX509(data []byte, collection *StixCollection) error {
	var v X509Certificate
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	collection.Add(&v)
	return nil
}

type peakObject struct {
	Type StixType `json:"type"`
}
