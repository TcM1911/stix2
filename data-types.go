// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Binary data type represents a sequence of bytes. The JSON MTI serialization
// represents this as a base64-­encoded string. Other serializations SHOULD use
// a native binary type, if available.
type Binary []byte

// String turns the Binary data into a base64 encoded string.
func (typ Binary) String() string {
	return base64.StdEncoding.EncodeToString([]byte(typ))
}

// UnmarshalJSON extracts the binary data from the json data.
func (typ *Binary) UnmarshalJSON(b []byte) error {
	if len(b) < 2 {
		return nil
	}
	t := string(b[1 : len(b)-1])
	data, err := base64.StdEncoding.DecodeString(t)
	if err != nil {
		return err
	}
	*typ = data
	return nil
}

// MarshalJSON converts the binary data to base64 for JSON serialization.
func (typ Binary) MarshalJSON() ([]byte, error) {
	if len(typ) < 1 {
		return []byte{}, nil
	}
	return []byte("\"" + typ.String() + "\""), nil
}

// Hex type encodes an array of octets (8-bit bytes) as hexadecimal. The string
// MUST consist of an even number of hexadecimal characters, which are the
// digits '0' through '9' and the lower-case letters 'a' through 'f'. In order
// to allow pattern matching on custom objects.
type Hex string

const (
	// MD5 is the MD5 message digest algorithm. The corresponding hash string
	// for this value MUST be a valid MD5 message digest as defined in
	// [RFC1321].
	MD5 HashAlgorithm = "MD5"
	// SHA1 is the SHA­-1 (secure-­hash algorithm 1) cryptographic hash
	// function. The corresponding hash string for this value MUST be a valid
	// SHA-1 message digest as defined in [RFC3174].
	SHA1 HashAlgorithm = "SHA-1"
	// SHA256 is the SHA-­256 cryptographic hash function (part of the SHA­2
	// family). The corresponding hash string for this value MUST be a valid
	// SHA-256 message digest as defined in [RFC6234].
	SHA256 HashAlgorithm = "SHA-256"
	// SHA512 is the SHA-­512 cryptographic hash function (part of the SHA­2
	// family). The corresponding hash string for this value MUST be a valid
	// SHA-512 message digest as defined in [RFC6234].
	SHA512 HashAlgorithm = "SHA-512"
	// SHA3256 is the SHA3-256 cryptographic hash function. The corresponding
	// hash string for this value MUST be a valid SHA3-256 message digest as
	// defined in [FIPS202].
	SHA3256 HashAlgorithm = "SHA3-256"
	// SHA3512 is the SHA3-512 cryptographic hash function. The corresponding
	// hash string for this value MUST be a valid SHA3-512 message digest as
	// defined in [FIPS202].
	SHA3512 HashAlgorithm = "SHA3-512"
	// SSDEEP is he ssdeep fuzzy hashing algorithm. The corresponding hash
	// string for this value MUST be a valid piecewise hash as defined in the
	// [SSDEEP] specification.
	SSDEEP HashAlgorithm = "SSDEEP"
)

// HashAlgorithm is a vocabulary of hashing algorithms.
type HashAlgorithm string

// ExternalReference is used to describe pointers to information represented
// outside of STIX. For example, a Malware object could use an external
// reference to indicate an ID for that malware in an external database or a
// report could use references to represent source material.
type ExternalReference struct {
	// Name of the source that the external-reference is defined within
	// (system, registry, organization, etc.).
	Name string `json:"source_name"`
	// Description is a human readable description.
	Description string `json:"description,omitempty"`
	// URL is a reference to an external resource.
	URL string `json:"url,omitempty"`
	// Hashes specifies a dictionary of hashes for the contents of the url.
	// This SHOULD be provided when the url property is present.
	Hashes Hashes `json:"hashes,omitempty"`
	// ExternalID is an identifier for the external reference content.
	ExternalID string `json:"external_id,omitempty"`
}

// NewExternalReference creates a new external reference.
func NewExternalReference(name, description, url, externalID string, hashes map[HashAlgorithm]string) (*ExternalReference, error) {
	if name == "" {
		return nil, ErrPropertyMissing
	}
	if description == "" && url == "" && externalID == "" {
		return nil, ErrPropertyMissing
	}
	return &ExternalReference{
		Name:        name,
		Description: description,
		URL:         url,
		Hashes:      hashes,
		ExternalID:  externalID,
	}, nil
}

// ParseExternalReference parses external reference JSON data to
// *ExternalReference struct
func ParseExternalReference(data []byte) (*ExternalReference, error) {
	var er *ExternalReference
	err := json.Unmarshal(data, &er)
	return er, err
}

// Hashes represents one or more cryptographic hashes, as a special set of
// key/value pairs. Accordingly, the name of each hashing algorithm MUST be
// specified as a key in the dictionary and MUST identify the name of the
// hashing algorithm used to generate the corresponding value. This name SHOULD
// come from one of the values defined in the hash-algorithm-ov.
//
// Dictionary keys MUST be unique in each hashes property, MUST be in ASCII,
// and are limited to the characters a-z (lowercase ASCII), A-Z (uppercase
// ASCII), numerals 0-9, hyphen (-), and underscore (_). Dictionary keys MUST
// have a minimum length of 3 ASCII characters and MUST be no longer than 250
// ASCII characters in length.
//
// To enhance compatibility, the SHA-256 hash SHOULD be used whenever possible.
type Hashes map[HashAlgorithm]string

func (h Hashes) getIDContribution() string {
	if v, ok := h[MD5]; ok {
		return fmt.Sprintf("{\"MD5\":\"%s\"}", v)
	}
	if v, ok := h[SHA1]; ok {
		return fmt.Sprintf("{\"SHA-1\":\"%s\"}", v)
	}
	if v, ok := h[SHA256]; ok {
		return fmt.Sprintf("{\"SHA-256\":\"%s\"}", v)
	}
	if v, ok := h[SHA512]; ok {
		return fmt.Sprintf("{\"SHA-512\":\"%s\"}", v)
	}
	return ""
}

// Identifier uniquely identifies a STIX Object and MAY do so in a
// deterministic way. A deterministic identifier means that the identifier
// generated by more than one producer for the exact same STIX Object using the
// same namespace, "ID Contributing Properties", and UUID method will have the
// exact same identifier value.
type Identifier string

// ForType checks if the identifier is for the StixType.
func (i Identifier) ForType(typ StixType) bool {
	return strings.Index(string(i), string(typ)) == 0
}

// ForTypes checks if the Identifier is for any of the types given.
// True is returned if one of the types matches.
func (i Identifier) ForTypes(typ ...StixType) bool {
	for _, t := range typ {
		if i.ForType(t) {
			return true
		}
	}
	return false
}

// CyberObservableNamespace is the UUIDv5 namespace for for STIX
// Cyber-observable Object.
var CyberObservableNamespace = uuid.MustParse("00abedb4-aa42-466c-9c01-fed23315a9b7")

// NewIdentifier creates a new Identifier. The Identifier uses the StixType and
// a UUIDv4 to produce a random ID. This function should be used when
// generating identifiers for TIX Domain Objects, STIX Relationship Objects,
// STIX Meta Objects, and STIX Bundle Object.
func NewIdentifier(typ StixType) (Identifier, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return "", err
	}
	return Identifier(fmt.Sprintf("%s--%s", typ, id)), nil
}

// NewObservableIdenfier creates a new STIX Cyber-observable Object identifier.
func NewObservableIdenfier(value string, typ StixType) Identifier {
	id := uuid.NewSHA1(CyberObservableNamespace, []byte(value))
	return Identifier(fmt.Sprintf("%s--%s", typ, id))
}

// IsValidIdentifier checks if the Identifier is of valid format.
func IsValidIdentifier(id Identifier) bool {
	parts := strings.Split(string(id), "--")
	if len(parts) != 2 {
		return false
	}
	// TODO: Add check for the Stix type part.
	_, err := uuid.Parse(parts[1])
	if err != nil {
		return false
	}
	return true
}

// StixType is type strings used in Stix objects.
type StixType string

const (
	// TypeAS is used for AS type.
	TypeAS StixType = "autonomous-system"
	// TypeArtifact is used for artifact type.
	TypeArtifact StixType = "artifact"
	// TypeAttackPattern is used for attack-pattern type.
	TypeAttackPattern StixType = "attack-pattern"
	// TypeCampaign is used for campaign type.
	TypeCampaign StixType = "campaign"
	// TypeCourseOfAction is used for course of action type.
	TypeCourseOfAction StixType = "course-of-action"
	// TypeDirectory is used for directory type.
	TypeDirectory StixType = "directory"
	// TypeDomainName is used for domain name types.
	TypeDomainName StixType = "domain-name"
	// TypeEmailAddress is used for email address type.
	TypeEmailAddress StixType = "email-addr"
	// TypeEmailMIME is used for email Mime type.
	TypeEmailMIME StixType = "mime-part-type"
	// TypeEmailMessage is used for email message type.
	TypeEmailMessage StixType = "email-message"
	// TypeFile is used for file types.
	TypeFile StixType = "file"
	// TypeGrouping is used for grouping type.
	TypeGrouping StixType = "grouping"
	// TypeIPv4Addr is used for IPv4 address types.
	TypeIPv4Addr StixType = "ipv4-addr"
	// TypeIPv6Addr is used for IPv6 address types.
	TypeIPv6Addr StixType = "ipv6-addr"
	// TypeIdentity is used for identity types.
	TypeIdentity StixType = "identity"
	// TypeIndicator is used for indicator types.
	TypeIndicator StixType = "indicator"
	// TypeInfrastructure is used for infrastructure type.
	TypeInfrastructure StixType = "infrastructure"
	// TypeIntrusionSet is used for intrusion set type.
	TypeIntrusionSet StixType = "intrusion-set"
	// TypeLanguageContent is used for language content type.
	TypeLanguageContent StixType = "language-content"
	// TypeLocation is used for location type.
	TypeLocation StixType = "location"
	// TypeMACAddress is used for MAC address type.
	TypeMACAddress StixType = "mac-addr"
	// TypeMalware is used for malware type.
	TypeMalware StixType = "malware"
	// TypeMalwareAnalysis is used for file types.
	TypeMalwareAnalysis StixType = "malware-analysis"
	// TypeMarkingDefinition is used for marking definition type.
	TypeMarkingDefinition StixType = "marking-definition"
	// TypeMutex is used for mutex type.
	TypeMutex StixType = "mutex"
	// TypeNetworkTraffic is used for network traffic type.
	TypeNetworkTraffic StixType = "network-traffic"
	// TypeNote is used for the note type.
	TypeNote StixType = "note"
	// TypeObservedData is used for observed data type.
	TypeObservedData StixType = "observed-data"
	// TypeOpinion is used for the opinion type.
	TypeOpinion StixType = "opinion"
	// TypeProcess is used for process type.
	TypeProcess StixType = "process"
	// TypeRegistryKey is used for registry key type.
	TypeRegistryKey StixType = "windows-registry-key"
	// TypeRelationship is used for relationship types.
	TypeRelationship StixType = "relationship"
	// TypeReport is used for the report type.
	TypeReport StixType = "report"
	// TypeSighting is used for sighting types.
	TypeSighting StixType = "sighting"
	// TypeSoftware is used for software type.
	TypeSoftware StixType = "software"
	// TypeThreatActor is used for threat actor type.
	TypeThreatActor StixType = "threat-actor"
	// TypeTool is used for tool type.
	TypeTool StixType = "tool"
	// TypeURL is used for URL types.
	TypeURL StixType = "url"
	// TypeUserAccount is used for user account type.
	TypeUserAccount StixType = "user-account"
	// TypeVulnerability is used for vulnerability type.
	TypeVulnerability StixType = "vulnerability"
	// TypeX509Certificate is used for X.509 certificate type.
	TypeX509Certificate StixType = "x509-certificate"
)

// AllTypes is a list of all STIX types.
var AllTypes = []StixType{
	TypeAS,
	TypeArtifact,
	TypeAttackPattern,
	TypeCampaign,
	TypeCourseOfAction,
	TypeDirectory,
	TypeDomainName,
	TypeEmailAddress,
	TypeEmailMIME,
	TypeEmailMessage,
	TypeFile,
	TypeGrouping,
	TypeIPv4Addr,
	TypeIPv6Addr,
	TypeIdentity,
	TypeIndicator,
	TypeInfrastructure,
	TypeIntrusionSet,
	TypeLanguageContent,
	TypeLocation,
	TypeMACAddress,
	TypeMalware,
	TypeMalwareAnalysis,
	TypeMarkingDefinition,
	TypeMutex,
	TypeNetworkTraffic,
	TypeNote,
	TypeObservedData,
	TypeOpinion,
	TypeProcess,
	TypeRegistryKey,
	TypeRelationship,
	TypeReport,
	TypeSighting,
	TypeSoftware,
	TypeThreatActor,
	TypeTool,
	TypeURL,
	TypeUserAccount,
	TypeVulnerability,
	TypeX509Certificate,
}

const (
	// ExtArchive is used as key for archive extension.
	ExtArchive = "archive-ext"
	// ExtNTFS is used as key for ntfs extension.
	ExtNTFS = "ntfs-ext"
	// ExtPDF is used as key for pdf extension.
	ExtPDF = "pdf-ext"
	// ExtRasterImage is used as key for raster image extension.
	ExtRasterImage = "raster-image-ext"
	// ExtWindowsPEBinary is used as key for Windows PE binary extension.
	ExtWindowsPEBinary = "windows-pebinary-ext"
	// ExtHTTPRequest is used for HTTP request extension.
	ExtHTTPRequest = "http-request-ext"
	// ExtICMP is used for ICMP extension.
	ExtICMP = "icmp-ext"
	// ExtSocket is used for socket extension.
	ExtSocket = "socket-ext"
	// ExtTCP is used for TCP extension.
	ExtTCP = "tcp-ext"
	// ExtWindowsProcess is used for Windows process extension.
	ExtWindowsProcess = "windows-process-ext"
	// ExtWindowsService is used for Windows service extension.
	ExtWindowsService = "windows-service-ext"
	// ExtUnixAccount is used for UNIX user account extension.
	ExtUnixAccount = "unix-account-ext"
)

// KillChainPhase  represents a phase in a kill chain, which describes the
// various phases an attacker may undertake in order to achieve their
// objectives. When referencing the Lockheed Martin Cyber Kill Chain™, the
// kill_chain_name property MUST be LockheedMartinCyberKillChain.
type KillChainPhase struct {
	// Name is the name of the kill chain. The value of this property SHOULD be
	// all lowercase and SHOULD use hyphens instead of spaces or underscores as
	// word separators.
	Name string `json:"kill_chain_name"`
	// Phase is the name of the phase in the kill chain. The value of this
	// property SHOULD be all lowercase and SHOULD use hyphens instead of
	// spaces or underscores as word separators.
	Phase string `json:"phase_name"`
}

// LockheedMartinCyberKillChain is the kill chain name for Lockheed Martin
// Cyber Kill Chain™.
const LockheedMartinCyberKillChain = "lockheed-martin-cyber-kill-chain"

// NewKillChainPhase creates a new KillChainPhase, both arguments are required.
func NewKillChainPhase(name, phase string) (*KillChainPhase, error) {
	if name == "" || phase == "" {
		return nil, ErrPropertyMissing
	}
	return &KillChainPhase{Name: name, Phase: phase}, nil
}

// ParseKillChainPhase parses a KillChainPhase object from the JSON data.
func ParseKillChainPhase(data []byte) (*KillChainPhase, error) {
	var kc *KillChainPhase
	err := json.Unmarshal(data, &kc)
	return kc, err
}

// Timestamp is a RFC 3339-formatted timestamp.
type Timestamp struct {
	time.Time
}

// String returns a string representation of the timestamp.
func (t *Timestamp) String() string {
	return t.Format(time.RFC3339Nano)
}

// MarshalJSON  creates a RFC 3339-formatted timestamp.
func (t *Timestamp) MarshalJSON() ([]byte, error) {
	return []byte(`"` + t.String() + `"`), nil
}

// UnmarshalJSON is extracting the timestamp form json.
func (t *Timestamp) UnmarshalJSON(b []byte) error {
	// Removing the two " and parse the timestamp.
	stamp, err := time.Parse(time.RFC3339Nano, string(b[1:len(b)-1]))
	if err != nil {
		return err
	}
	*t = Timestamp{stamp}
	return nil
}
