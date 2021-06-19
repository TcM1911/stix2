// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

// STIXObject is a generic representation of a STIX object.
type STIXObject interface {
	// GetID returns the identifier for the object.
	GetID() Identifier
	// GetType returns the object's type.
	GetType() STIXType
	// GetCreated returns the created time for the STIX object. If the object
	// does not have a time defined, nil is returned.
	GetCreated() *time.Time
	// GetModified returns the modified time for the STIX object. If the object
	// does not have a time defined, nil is returned.
	GetModified() *time.Time
}

// CollectionOption is an optional parameter when constructing a Colletion.
type CollectionOption func(c *Collection)

// NoSortOption instructs the collection to not track the order items have been
// added. By default, GetAll items returns the objects in the order they were
// added. If this option is provided, the order returned is non-deterministic.
func NoSortOption() CollectionOption {
	return func(c *Collection) {
		c.noSort = true
	}
}

// New creates a new Collection.
func New(opts ...CollectionOption) *Collection {
	c := &Collection{}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// Collection is a collection of STIX objects. This object is not part of the
// STIX specification.
type Collection struct {
	objects map[STIXType]map[Identifier]interface{}
	objinit sync.Once

	// Options
	noSort bool
	order  []Identifier
}

// Get returns the object with matching ID or nil if it does not exist in the
// collection.
func (c *Collection) Get(id Identifier) STIXObject {
	parts := strings.Split(string(id), "--")
	if len(parts) != 2 {
		// Incorrect format for the ID.
		return nil
	}
	bucket, ok := c.objects[STIXType(parts[0])]
	if !ok {
		// No objects for this type.
		return nil
	}
	obj, ok := bucket[id]
	if !ok {
		// No object with the ID.
		return nil
	}
	return obj.(STIXObject)
}

// Add adds or updates an object in the collection.
func (c *Collection) Add(obj STIXObject) error {
	c.objinit.Do(func() {
		objectInit(c)
	})
	if !HasValidIdentifier(obj) {
		return fmt.Errorf("%s has an invalid identifier", obj.GetID())
	}
	bucket := c.objects[obj.GetType()]

	// Check if the item already exist.
	_, update := bucket[obj.GetID()]

	bucket[obj.GetID()] = obj

	// Add to the order if we should track it and item is new.
	if !c.noSort && !update {
		c.order = append(c.order, obj.GetID())
	}

	return nil
}

// AllObjects returns a slice of all STIXObjects that are in the collection.
func (c *Collection) AllObjects() []STIXObject {
	// If track the order, we use it to get all the objects. Otherwise, we have
	// to iterrate throw all buckets.

	if !c.noSort && len(c.order) != 0 {
		result := make([]STIXObject, 0, len(c.order))
		for _, id := range c.order {
			result = append(result, c.Get(id))
		}
		return result
	}

	// Scenario where we don't track the order.

	// Calculate the size of the array.
	size := 0
	for _, ar := range c.objects {
		size = size + len(ar)
	}

	result := make([]STIXObject, 0, size)
	for _, v := range c.objects {
		for _, vv := range v {
			result = append(result, vv.(STIXObject))
		}
	}
	return result
}

// ToBundle returns a STIX bundle with all the STIXObjects in the Collection.
func (c *Collection) ToBundle() (*Bundle, error) {
	return NewBundle(c.AllObjects()...)
}

// AS returns the AS with the identifier id.
func (c *Collection) AS(id Identifier) *AutonomousSystem {
	obj := c.getObject(TypeAutonomousSystem, id)
	if obj == nil {
		return nil
	}
	return obj.(*AutonomousSystem)
}

// ASs returns all the AS in the collection.
func (c *Collection) ASs() []*AutonomousSystem {
	data := make([]*AutonomousSystem, 0, len(c.objects[TypeAutonomousSystem]))
	for _, v := range c.objects[TypeAutonomousSystem] {
		data = append(data, v.(*AutonomousSystem))
	}
	return data
}

// Artifact returns the Artifact with the identifier id.
func (c *Collection) Artifact(id Identifier) *Artifact {
	obj := c.getObject(TypeArtifact, id)
	if obj == nil {
		return nil
	}
	return obj.(*Artifact)
}

// Artifacts returns all the Artifacts in the collection.
func (c *Collection) Artifacts() []*Artifact {
	data := make([]*Artifact, 0, len(c.objects[TypeArtifact]))
	for _, v := range c.objects[TypeArtifact] {
		data = append(data, v.(*Artifact))
	}
	return data
}

// AttackPattern returns the AttackPattern with the identifier id.
func (c *Collection) AttackPattern(id Identifier) *AttackPattern {
	obj := c.getObject(TypeAttackPattern, id)
	if obj == nil {
		return nil
	}
	return obj.(*AttackPattern)
}

// AttackPatterns returns all the AttackPatterns in the collection.
func (c *Collection) AttackPatterns() []*AttackPattern {
	data := make([]*AttackPattern, 0, len(c.objects[TypeAttackPattern]))
	for _, v := range c.objects[TypeAttackPattern] {
		data = append(data, v.(*AttackPattern))
	}
	return data
}

// Campaign returns the Campaign with the identifier id.
func (c *Collection) Campaign(id Identifier) *Campaign {
	obj := c.getObject(TypeCampaign, id)
	if obj == nil {
		return nil
	}
	return obj.(*Campaign)
}

// Campaigns returns all the Campaigns in the collection.
func (c *Collection) Campaigns() []*Campaign {
	data := make([]*Campaign, 0, len(c.objects[TypeCampaign]))
	for _, v := range c.objects[TypeCampaign] {
		data = append(data, v.(*Campaign))
	}
	return data
}

// CourseOfAction returns the CourseOfAction with the identifier id.
func (c *Collection) CourseOfAction(id Identifier) *CourseOfAction {
	obj := c.getObject(TypeCourseOfAction, id)
	if obj == nil {
		return nil
	}
	return obj.(*CourseOfAction)
}

// CourseOfActions returns all the CourseOfActions in the collection.
func (c *Collection) CourseOfActions() []*CourseOfAction {
	data := make([]*CourseOfAction, 0, len(c.objects[TypeCourseOfAction]))
	for _, v := range c.objects[TypeCourseOfAction] {
		data = append(data, v.(*CourseOfAction))
	}
	return data
}

// Directory returns the Directory with the identifier id.
func (c *Collection) Directory(id Identifier) *Directory {
	obj := c.getObject(TypeDirectory, id)
	if obj == nil {
		return nil
	}
	return obj.(*Directory)
}

// Directories returns all the Directories in the collection.
func (c *Collection) Directories() []*Directory {
	data := make([]*Directory, 0, len(c.objects[TypeDirectory]))
	for _, v := range c.objects[TypeDirectory] {
		data = append(data, v.(*Directory))
	}
	return data
}

// DomainName returns the DomainName with the identifier id.
func (c *Collection) DomainName(id Identifier) *DomainName {
	obj := c.getObject(TypeDomainName, id)
	if obj == nil {
		return nil
	}
	return obj.(*DomainName)
}

// DomainNames returns all the DomainNames in the collection.
func (c *Collection) DomainNames() []*DomainName {
	data := make([]*DomainName, 0, len(c.objects[TypeDomainName]))
	for _, v := range c.objects[TypeDomainName] {
		data = append(data, v.(*DomainName))
	}
	return data
}

// EmailAddress returns the EmailAddress with the identifier id.
func (c *Collection) EmailAddress(id Identifier) *EmailAddress {
	obj := c.getObject(TypeEmailAddress, id)
	if obj == nil {
		return nil
	}
	return obj.(*EmailAddress)
}

// EmailAddresses returns all the EmailAddresses in the collection.
func (c *Collection) EmailAddresses() []*EmailAddress {
	data := make([]*EmailAddress, 0, len(c.objects[TypeEmailAddress]))
	for _, v := range c.objects[TypeEmailAddress] {
		data = append(data, v.(*EmailAddress))
	}
	return data
}

// EmailMessage returns the EmailMessage with the identifier id.
func (c *Collection) EmailMessage(id Identifier) *EmailMessage {
	obj := c.getObject(TypeEmailMessage, id)
	if obj == nil {
		return nil
	}
	return obj.(*EmailMessage)
}

// EmailMessages returns all the EmailMessages in the collection.
func (c *Collection) EmailMessages() []*EmailMessage {
	data := make([]*EmailMessage, 0, len(c.objects[TypeEmailMessage]))
	for _, v := range c.objects[TypeEmailMessage] {
		data = append(data, v.(*EmailMessage))
	}
	return data
}

// File returns the File with the identifier id.
func (c *Collection) File(id Identifier) *File {
	obj := c.getObject(TypeFile, id)
	if obj == nil {
		return nil
	}
	return obj.(*File)
}

// Files returns all the Files in the collection.
func (c *Collection) Files() []*File {
	data := make([]*File, 0, len(c.objects[TypeFile]))
	for _, v := range c.objects[TypeFile] {
		data = append(data, v.(*File))
	}
	return data
}

// Group returns the Group with the identifier id.
func (c *Collection) Group(id Identifier) *Grouping {
	obj := c.getObject(TypeGrouping, id)
	if obj == nil {
		return nil
	}
	return obj.(*Grouping)
}

// Groups returns all the Groups in the collection.
func (c *Collection) Groups() []*Grouping {
	data := make([]*Grouping, 0, len(c.objects[TypeGrouping]))
	for _, v := range c.objects[TypeGrouping] {
		data = append(data, v.(*Grouping))
	}
	return data
}

// IPv4Address returns the IPv4Address with the identifier id.
func (c *Collection) IPv4Address(id Identifier) *IPv4Address {
	obj := c.getObject(TypeIPv4Addr, id)
	if obj == nil {
		return nil
	}
	return obj.(*IPv4Address)
}

// IPv4Addresses returns all the IPv4Addresses in the collection.
func (c *Collection) IPv4Addresses() []*IPv4Address {
	data := make([]*IPv4Address, 0, len(c.objects[TypeIPv4Addr]))
	for _, v := range c.objects[TypeIPv4Addr] {
		data = append(data, v.(*IPv4Address))
	}
	return data
}

// IPv6Address returns the IPv6Address with the identifier id.
func (c *Collection) IPv6Address(id Identifier) *IPv6Address {
	obj := c.getObject(TypeIPv6Addr, id)
	if obj == nil {
		return nil
	}
	return obj.(*IPv6Address)
}

// IPv6Addresses returns all the IPv6Addresses in the collection.
func (c *Collection) IPv6Addresses() []*IPv6Address {
	data := make([]*IPv6Address, 0, len(c.objects[TypeIPv6Addr]))
	for _, v := range c.objects[TypeIPv6Addr] {
		data = append(data, v.(*IPv6Address))
	}
	return data
}

// Identity returns the Identity with the identifier id.
func (c *Collection) Identity(id Identifier) *Identity {
	obj := c.getObject(TypeIdentity, id)
	if obj == nil {
		return nil
	}
	return obj.(*Identity)
}

// Identities returns all the Identities in the collection.
func (c *Collection) Identities() []*Identity {
	data := make([]*Identity, 0, len(c.objects[TypeIdentity]))
	for _, v := range c.objects[TypeIdentity] {
		data = append(data, v.(*Identity))
	}
	return data
}

// Indicator returns the Indicator with the identifier id.
func (c *Collection) Indicator(id Identifier) *Indicator {
	obj := c.getObject(TypeIndicator, id)
	if obj == nil {
		return nil
	}
	return obj.(*Indicator)
}

// Indicators returns all the Indicators in the collection.
func (c *Collection) Indicators() []*Indicator {
	data := make([]*Indicator, 0, len(c.objects[TypeIndicator]))
	for _, v := range c.objects[TypeIndicator] {
		data = append(data, v.(*Indicator))
	}
	return data
}

// Infrastructure returns the Infrastructure with the identifier id.
func (c *Collection) Infrastructure(id Identifier) *Infrastructure {
	obj := c.getObject(TypeInfrastructure, id)
	if obj == nil {
		return nil
	}
	return obj.(*Infrastructure)
}

// Infrastructures returns all the Infrastructures in the collection.
func (c *Collection) Infrastructures() []*Infrastructure {
	data := make([]*Infrastructure, 0, len(c.objects[TypeInfrastructure]))
	for _, v := range c.objects[TypeInfrastructure] {
		data = append(data, v.(*Infrastructure))
	}
	return data
}

// IntrusionSet returns the IntrusionSet with the identifier id.
func (c *Collection) IntrusionSet(id Identifier) *IntrusionSet {
	obj := c.getObject(TypeIntrusionSet, id)
	if obj == nil {
		return nil
	}
	return obj.(*IntrusionSet)
}

// IntrusionSets returns all the IntrusionSets in the collection.
func (c *Collection) IntrusionSets() []*IntrusionSet {
	data := make([]*IntrusionSet, 0, len(c.objects[TypeIntrusionSet]))
	for _, v := range c.objects[TypeIntrusionSet] {
		data = append(data, v.(*IntrusionSet))
	}
	return data
}

// LanguageContent returns the LanguageContent with the identifier id.
func (c *Collection) LanguageContent(id Identifier) *LanguageContent {
	obj := c.getObject(TypeLanguageContent, id)
	if obj == nil {
		return nil
	}
	return obj.(*LanguageContent)
}

// LanguageContents returns all the LanguageContents in the collection.
func (c *Collection) LanguageContents() []*LanguageContent {
	data := make([]*LanguageContent, 0, len(c.objects[TypeLanguageContent]))
	for _, v := range c.objects[TypeLanguageContent] {
		data = append(data, v.(*LanguageContent))
	}
	return data
}

// Location returns the Location with the identifier id.
func (c *Collection) Location(id Identifier) *Location {
	obj := c.getObject(TypeLocation, id)
	if obj == nil {
		return nil
	}
	return obj.(*Location)
}

// Locations returns all the Locations in the collection.
func (c *Collection) Locations() []*Location {
	data := make([]*Location, 0, len(c.objects[TypeLocation]))
	for _, v := range c.objects[TypeLocation] {
		data = append(data, v.(*Location))
	}
	return data
}

// MAC returns the MAC with the identifier id.
func (c *Collection) MAC(id Identifier) *MACAddress {
	obj := c.getObject(TypeMACAddress, id)
	if obj == nil {
		return nil
	}
	return obj.(*MACAddress)
}

// MACs returns all the MACs in the collection.
func (c *Collection) MACs() []*MACAddress {
	data := make([]*MACAddress, 0, len(c.objects[TypeMACAddress]))
	for _, v := range c.objects[TypeMACAddress] {
		data = append(data, v.(*MACAddress))
	}
	return data
}

// Malware returns the Malware with the identifier id.
func (c *Collection) Malware(id Identifier) *Malware {
	obj := c.getObject(TypeMalware, id)
	if obj == nil {
		return nil
	}
	return obj.(*Malware)
}

// AllMalware returns all the Malware in the collection.
func (c *Collection) AllMalware() []*Malware {
	data := make([]*Malware, 0, len(c.objects[TypeMalware]))
	for _, v := range c.objects[TypeMalware] {
		data = append(data, v.(*Malware))
	}
	return data
}

// MalwareAnalysis returns the MalwareAnalysis with the identifier id.
func (c *Collection) MalwareAnalysis(id Identifier) *MalwareAnalysis {
	obj := c.getObject(TypeMalwareAnalysis, id)
	if obj == nil {
		return nil
	}
	return obj.(*MalwareAnalysis)
}

// MalwareAnalyses returns all the MalwareAnalyses in the collection.
func (c *Collection) MalwareAnalyses() []*MalwareAnalysis {
	data := make([]*MalwareAnalysis, 0, len(c.objects[TypeMalwareAnalysis]))
	for _, v := range c.objects[TypeMalwareAnalysis] {
		data = append(data, v.(*MalwareAnalysis))
	}
	return data
}

// MarkingDefinition returns the MarkingDefinition with the identifier id.
func (c *Collection) MarkingDefinition(id Identifier) *MarkingDefinition {
	obj := c.getObject(TypeMarkingDefinition, id)
	if obj == nil {
		return nil
	}
	return obj.(*MarkingDefinition)
}

// MarkingDefinitions returns all the MarkingDefinitions in the collection.
func (c *Collection) MarkingDefinitions() []*MarkingDefinition {
	data := make([]*MarkingDefinition, 0, len(c.objects[TypeMarkingDefinition]))
	for _, v := range c.objects[TypeMarkingDefinition] {
		data = append(data, v.(*MarkingDefinition))
	}
	return data
}

// Mutex returns the Mutex with the identifier id.
func (c *Collection) Mutex(id Identifier) *Mutex {
	obj := c.getObject(TypeMutex, id)
	if obj == nil {
		return nil
	}
	return obj.(*Mutex)
}

// Mutexes returns all the Mutexes in the collection.
func (c *Collection) Mutexes() []*Mutex {
	data := make([]*Mutex, 0, len(c.objects[TypeMutex]))
	for _, v := range c.objects[TypeMutex] {
		data = append(data, v.(*Mutex))
	}
	return data
}

// NetworkTraffic returns the NetworkTraffic with the identifier id.
func (c *Collection) NetworkTraffic(id Identifier) *NetworkTraffic {
	obj := c.getObject(TypeNetworkTraffic, id)
	if obj == nil {
		return nil
	}
	return obj.(*NetworkTraffic)
}

// AllNetworkTraffic returns all the NetworkTraffic in the collection.
func (c *Collection) AllNetworkTraffic() []*NetworkTraffic {
	data := make([]*NetworkTraffic, 0, len(c.objects[TypeNetworkTraffic]))
	for _, v := range c.objects[TypeNetworkTraffic] {
		data = append(data, v.(*NetworkTraffic))
	}
	return data
}

// Note returns the Note with the identifier id.
func (c *Collection) Note(id Identifier) *Note {
	obj := c.getObject(TypeNote, id)
	if obj == nil {
		return nil
	}
	return obj.(*Note)
}

// Notes returns all the Notes in the collection.
func (c *Collection) Notes() []*Note {
	data := make([]*Note, 0, len(c.objects[TypeNote]))
	for _, v := range c.objects[TypeNote] {
		data = append(data, v.(*Note))
	}
	return data
}

// ObservedData returns the ObservedData with the identifier id.
func (c *Collection) ObservedData(id Identifier) *ObservedData {
	obj := c.getObject(TypeObservedData, id)
	if obj == nil {
		return nil
	}
	return obj.(*ObservedData)
}

// AllObservedData returns all the ObservedData in the collection.
func (c *Collection) AllObservedData() []*ObservedData {
	data := make([]*ObservedData, 0, len(c.objects[TypeObservedData]))
	for _, v := range c.objects[TypeObservedData] {
		data = append(data, v.(*ObservedData))
	}
	return data
}

// Opinion returns the Opinion with the identifier id.
func (c *Collection) Opinion(id Identifier) *Opinion {
	obj := c.getObject(TypeOpinion, id)
	if obj == nil {
		return nil
	}
	return obj.(*Opinion)
}

// Opinions returns all the Opinions in the collection.
func (c *Collection) Opinions() []*Opinion {
	data := make([]*Opinion, 0, len(c.objects[TypeOpinion]))
	for _, v := range c.objects[TypeOpinion] {
		data = append(data, v.(*Opinion))
	}
	return data
}

// Process returns the Process with the identifier id.
func (c *Collection) Process(id Identifier) *Process {
	obj := c.getObject(TypeProcess, id)
	if obj == nil {
		return nil
	}
	return obj.(*Process)
}

// Processes returns all the Processes in the collection.
func (c *Collection) Processes() []*Process {
	data := make([]*Process, 0, len(c.objects[TypeProcess]))
	for _, v := range c.objects[TypeProcess] {
		data = append(data, v.(*Process))
	}
	return data
}

// RegistryKey returns the RegistryKey with the identifier id.
func (c *Collection) RegistryKey(id Identifier) *RegistryKey {
	obj := c.getObject(TypeRegistryKey, id)
	if obj == nil {
		return nil
	}
	return obj.(*RegistryKey)
}

// RegistryKeys returns all the RegistryKeys in the collection.
func (c *Collection) RegistryKeys() []*RegistryKey {
	data := make([]*RegistryKey, 0, len(c.objects[TypeRegistryKey]))
	for _, v := range c.objects[TypeRegistryKey] {
		data = append(data, v.(*RegistryKey))
	}
	return data
}

// Relationship returns the Relationship with the identifier id.
func (c *Collection) Relationship(id Identifier) *Relationship {
	obj := c.getObject(TypeRelationship, id)
	if obj == nil {
		return nil
	}
	return obj.(*Relationship)
}

// Relationships returns all the Relationships in the collection.
func (c *Collection) Relationships() []*Relationship {
	data := make([]*Relationship, 0, len(c.objects[TypeRelationship]))
	for _, v := range c.objects[TypeRelationship] {
		data = append(data, v.(*Relationship))
	}
	return data
}

// Report returns the Report with the identifier id.
func (c *Collection) Report(id Identifier) *Report {
	obj := c.getObject(TypeReport, id)
	if obj == nil {
		return nil
	}
	return obj.(*Report)
}

// Reports returns all the Reports in the collection.
func (c *Collection) Reports() []*Report {
	data := make([]*Report, 0, len(c.objects[TypeReport]))
	for _, v := range c.objects[TypeReport] {
		data = append(data, v.(*Report))
	}
	return data
}

// Sighting returns the Sighting with the identifier id.
func (c *Collection) Sighting(id Identifier) *Sighting {
	obj := c.getObject(TypeSighting, id)
	if obj == nil {
		return nil
	}
	return obj.(*Sighting)
}

// Sightings returns all the Sightings in the collection.
func (c *Collection) Sightings() []*Sighting {
	data := make([]*Sighting, 0, len(c.objects[TypeSighting]))
	for _, v := range c.objects[TypeSighting] {
		data = append(data, v.(*Sighting))
	}
	return data
}

// Software returns the Software with the identifier id.
func (c *Collection) Software(id Identifier) *Software {
	obj := c.getObject(TypeSoftware, id)
	if obj == nil {
		return nil
	}
	return obj.(*Software)
}

// AllSoftware returns all the Software in the collection.
func (c *Collection) AllSoftware() []*Software {
	data := make([]*Software, 0, len(c.objects[TypeSoftware]))
	for _, v := range c.objects[TypeSoftware] {
		data = append(data, v.(*Software))
	}
	return data
}

// ThreatActor returns the ThreatActor with the identifier id.
func (c *Collection) ThreatActor(id Identifier) *ThreatActor {
	obj := c.getObject(TypeThreatActor, id)
	if obj == nil {
		return nil
	}
	return obj.(*ThreatActor)
}

// ThreatActors returns all the ThreatActors in the collection.
func (c *Collection) ThreatActors() []*ThreatActor {
	data := make([]*ThreatActor, 0, len(c.objects[TypeThreatActor]))
	for _, v := range c.objects[TypeThreatActor] {
		data = append(data, v.(*ThreatActor))
	}
	return data
}

// Tool returns the Tool with the identifier id.
func (c *Collection) Tool(id Identifier) *Tool {
	obj := c.getObject(TypeTool, id)
	if obj == nil {
		return nil
	}
	return obj.(*Tool)
}

// Tools returns all the Tools in the collection.
func (c *Collection) Tools() []*Tool {
	data := make([]*Tool, 0, len(c.objects[TypeTool]))
	for _, v := range c.objects[TypeTool] {
		data = append(data, v.(*Tool))
	}
	return data
}

// URL returns the URL with the identifier id.
func (c *Collection) URL(id Identifier) *URL {
	obj := c.getObject(TypeURL, id)
	if obj == nil {
		return nil
	}
	return obj.(*URL)
}

// URLs returns all the URLs in the collection.
func (c *Collection) URLs() []*URL {
	data := make([]*URL, 0, len(c.objects[TypeURL]))
	for _, v := range c.objects[TypeURL] {
		data = append(data, v.(*URL))
	}
	return data
}

// UserAccount returns the UserAccount with the identifier id.
func (c *Collection) UserAccount(id Identifier) *UserAccount {
	obj := c.getObject(TypeUserAccount, id)
	if obj == nil {
		return nil
	}
	return obj.(*UserAccount)
}

// UserAccounts returns all the UserAccounts in the collection.
func (c *Collection) UserAccounts() []*UserAccount {
	data := make([]*UserAccount, 0, len(c.objects[TypeUserAccount]))
	for _, v := range c.objects[TypeUserAccount] {
		data = append(data, v.(*UserAccount))
	}
	return data
}

// Vulnerability returns the Vulnerability with the identifier id.
func (c *Collection) Vulnerability(id Identifier) *Vulnerability {
	obj := c.getObject(TypeVulnerability, id)
	if obj == nil {
		return nil
	}
	return obj.(*Vulnerability)
}

// Vulnerabilities returns all the Vulnerabilities in the collection.
func (c *Collection) Vulnerabilities() []*Vulnerability {
	data := make([]*Vulnerability, 0, len(c.objects[TypeVulnerability]))
	for _, v := range c.objects[TypeVulnerability] {
		data = append(data, v.(*Vulnerability))
	}
	return data
}

// X509Certificate returns the X509Certificate with the identifier id.
func (c *Collection) X509Certificate(id Identifier) *X509Certificate {
	obj := c.getObject(TypeX509Certificate, id)
	if obj == nil {
		return nil
	}
	return obj.(*X509Certificate)
}

// X509Certificates returns all the X509Certificates in the collection.
func (c *Collection) X509Certificates() []*X509Certificate {
	data := make([]*X509Certificate, 0, len(c.objects[TypeX509Certificate]))
	for _, v := range c.objects[TypeX509Certificate] {
		data = append(data, v.(*X509Certificate))
	}
	return data
}

func (c *Collection) getObject(typ STIXType, id Identifier) interface{} {
	return c.objects[typ][id]
}

func objectInit(c *Collection) {
	c.objects = make(map[STIXType]map[Identifier]interface{})
	for _, k := range AllTypes {
		c.objects[k] = make(map[Identifier]interface{})
	}
}

// FromJSON parses JSON data and returns a Collection with the extracted
// objects.
func FromJSON(data []byte, opts ...CollectionOption) (*Collection, error) {
	collection := New(opts...)

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

func processBundle(collection *Collection, bundle Bundle) error {
	return processObjects(collection, bundle.Objects)
}

func processObjects(collection *Collection, objects []json.RawMessage) error {
	var peak peakObject
	var err error
	for _, data := range objects {
		err = json.Unmarshal(data, &peak)
		if err != nil {
			return err
		}

		var obj interface{}

		switch peak.Type {
		case TypeAutonomousSystem:
			obj = &AutonomousSystem{}
		case TypeArtifact:
			obj = &Artifact{}
		case TypeAttackPattern:
			obj = &AttackPattern{}
		case TypeCampaign:
			obj = &Campaign{}
		case TypeCourseOfAction:
			obj = &CourseOfAction{}
		case TypeDirectory:
			obj = &Directory{}
		case TypeDomainName:
			obj = &DomainName{}
		case TypeEmailAddress:
			obj = &EmailAddress{}
		case TypeEmailMessage:
			obj = &EmailMessage{}
		case TypeFile:
			obj = &File{}
		case TypeGrouping:
			obj = &Grouping{}
		case TypeIPv4Addr:
			obj = &IPv4Address{}
		case TypeIPv6Addr:
			obj = &IPv6Address{}
		case TypeIdentity:
			obj = &Identity{}
		case TypeIndicator:
			obj = &Indicator{}
		case TypeInfrastructure:
			obj = &Infrastructure{}
		case TypeIntrusionSet:
			obj = &IntrusionSet{}
		case TypeLanguageContent:
			obj = &LanguageContent{}
		case TypeLocation:
			obj = &Location{}
		case TypeMACAddress:
			obj = &MACAddress{}
		case TypeMalware:
			obj = &Malware{}
		case TypeMalwareAnalysis:
			obj = &MalwareAnalysis{}
		case TypeMarkingDefinition:
			obj = &MarkingDefinition{}
		case TypeMutex:
			obj = &Mutex{}
		case TypeNetworkTraffic:
			obj = &NetworkTraffic{}
		case TypeNote:
			obj = &Note{}
		case TypeObservedData:
			obj = &ObservedData{}
		case TypeOpinion:
			obj = &Opinion{}
		case TypeProcess:
			obj = &Process{}
		case TypeRegistryKey:
			obj = &RegistryKey{}
		case TypeRelationship:
			obj = &Relationship{}
		case TypeReport:
			obj = &Report{}
		case TypeSighting:
			obj = &Sighting{}
		case TypeSoftware:
			obj = &Software{}
		case TypeThreatActor:
			obj = &ThreatActor{}
		case TypeTool:
			obj = &Tool{}
		case TypeURL:
			obj = &URL{}
		case TypeUserAccount:
			obj = &UserAccount{}
		case TypeVulnerability:
			obj = &Vulnerability{}
		case TypeX509Certificate:
			obj = &X509Certificate{}
		default:
			return fmt.Errorf("%s is not a supported type", peak.Type)
		}

		err := json.Unmarshal(data, &obj)
		if err != nil {
			return fmt.Errorf("bad json data: %s", err)
		}

		err = collection.Add(obj.(STIXObject))
		if err != nil {
			return fmt.Errorf("failed to add %s object to collection: %s", peak.Type, err)
		}
	}
	return nil
}

type peakObject struct {
	Type STIXType `json:"type"`
}
