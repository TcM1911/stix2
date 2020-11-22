package stix2

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/ugorji/go/codec"
)

// STIXOption is an optional parameter when constructing an
// STIX object.
type STIXOption func(a StixObject) error

/*
	Options for Common Properties
*/

// OptionSpecVersion sets the STIX spec version. This option is valid for the types:
//		- STIX Domain Objects
//		- STIX Relationships Objects
//		- LanguageContent
//		- MarkingDefinition
//		- Bundle
func OptionSpecVersion(ver string) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "SpecVersion", ver, reflect.String)
	}
}

// OptionCreatedBy sets the created by by attribute. This option is valid for the types:
//		- STIX Domain Objects
//		- STIX Relationships Objects
//		- LanguageContent
//		- MarkingDefinition
func OptionCreatedBy(id Identifier) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "CreatedBy", id, reflect.String)
	}
}

// OptionCreated sets the created attribute. This option is valid for the types:
//		- STIX Domain Objects
//		- STIX Relationships Objects
//		- LanguageContent
//		- MarkingDefinition
func OptionCreated(t *Timestamp) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "Created", t, reflect.Ptr)
	}
}

// OptionModified sets the modified attribute. This option is valid for the types:
//		- STIX Domain Objects
//		- STIX Relationships Objects
//		- LanguageContent
func OptionModified(t *Timestamp) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "Modified", t, reflect.Ptr)
	}
}

// OptionRevoked sets the revoked attribute. This option is valid for the types:
//		- STIX Domain Objects
//		- STIX Relationships Objects
//		- LanguageContent
func OptionRevoked(rev bool) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "Revoked", rev, reflect.Bool)
	}
}

// OptionLabels sets the labels attribute. This option is valid for the types:
//		- STIX Domain Objects
//		- STIX Relationships Objects
//		- LanguageContent
func OptionLabels(labels []string) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "Labels", labels, reflect.Slice)
	}
}

// OptionConfidence sets the confidence attribute. This option is valid for the types:
//		- STIX Domain Objects
//		- STIX Relationships Objects
//		- LanguageContent
func OptionConfidence(confidence int) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "Confidence", confidence, reflect.Int)
	}
}

// OptionLang sets the lang attribute. This option is valid for the types:
//		- STIX Domain Objects
//		- STIX Relationships Objects
func OptionLang(lang string) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "Lang", lang, reflect.String)
	}
}

// OptionExternalReferences sets the external references attribute. This option is valid for the types:
//		- STIX Domain Objects
//		- STIX Relationships Objects
//		- LanguageContent
//		- MarkingDefinition
func OptionExternalReferences(refs []*ExternalReference) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "ExternalReferences", refs, reflect.Slice)
	}
}

// OptionObjectMarking sets the object marking attribute. This option is valid for the types:
//		- STIX Domain Objects
//		- STIX Cyber-observable Objects
//		- STIX Relationships Objects
//		- LanguageContent
//		- MarkingDefinition
func OptionObjectMarking(om []Identifier) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "ObjectMarking", om, reflect.Slice)
	}
}

// OptionGranularMarking sets the granular marking attribute. This option is valid for the types:
//		- STIX Domain Objects
//		- STIX Cyber-observable Objects
//		- STIX Relationships Objects
//		- LanguageContent
//		- MarkingDefinition
func OptionGranularMarking(gm []*GranularMarking) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "GranularMarking", gm, reflect.Slice)
	}
}

// OptionDefanged sets the defanged attribute. This option is valid for the types:
//		- STIX Cyber-observable Objects
func OptionDefanged(b bool) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "Defanged", b, reflect.Bool)
	}
}

// OptionExtension adds an extension. This option is valid for the types:
//		- STIX Cyber-observable Objects
func OptionExtension(name string, value interface{}) STIXOption {
	return func(obj StixObject) error {
		val, err := reflectValue(obj)
		if err != nil {
			return err
		}

		f := val.FieldByName("STIXCyberObservableObject")
		if !f.IsValid() || !f.CanSet() || f.Kind() != reflect.Struct {
			return fmt.Errorf("object is not a STIXCyberObservableObject")
		}

		// Extract extension

		ev := f.FieldByName("Extensions")
		if !ev.IsValid() || !ev.CanSet() {
			return fmt.Errorf("extension field not avaliable in the object")
		}

		ext, ok := ev.Interface().(map[string]json.RawMessage)
		if !ok {
			return fmt.Errorf("extensions field is of wrong type")
		}

		if ext == nil {
			ext = make(map[string]json.RawMessage)
		}

		// If error drop the data.
		buf := &bytes.Buffer{}
		c := codec.NewEncoder(buf, &codec.JsonHandle{})
		err = c.Encode(value)
		if err != nil {
			return fmt.Errorf("error when processing extension data: %w", err)
		}
		ext[name] = json.RawMessage(buf.Bytes())

		// Save the extensions field
		ev.Set(reflect.ValueOf(ext))

		return nil
	}
}

/*
	Other properties
*/

// OptionDescription sets the description attribute. This option is valid for the types:
//		- AttackPattern
//		- Campaign
//		- CourseOfAction
//		- Grouping
//		- Identity
//		- Indicator
//		- Infrastructure
//		- IntrusionSet
//		- Location
//		- Malware
//		- Report
//		- ThreatActor
//		- Tool
//		- Vulnerability
//		- Relationship
//		- Sighting
func OptionDescription(des string) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "Description", des, reflect.String)
	}
}

// OptionAliases sets the aliases attribute. This option is valid for the types:
//		- AttackPattern
//		- Campaign
//		- Infrastructure
//		- IntrusionSet
//		- Malware
//		- ThreatActor
//		- Tool
func OptionAliases(a []string) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "Aliases", a, reflect.Slice)
	}
}

// OptionKillChainPhase sets the kill chain phase attribute. This option is valid for the types:
//		- AttackPattern
//		- Indicator
//		- Infrastructure
//		- Malware
//		- Tool
func OptionKillChainPhase(k []*KillChainPhase) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "KillChainPhase", k, reflect.Slice)
	}
}

// OptionFirstSeen sets the first seen attribute. This option is valid for the types:
//		- Campaign
//		- Infrastructure
//		- IntrusionSet
//		- Malware
//		- ThreatActor
//		- Sighting
func OptionFirstSeen(t *Timestamp) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "FirstSeen", t, reflect.Ptr)
	}
}

// OptionLastSeen sets the last seen attribute. This option is valid for the types:
//		- Campaign
//		- Infrastructure
//		- IntrusionSet
//		- Malware
//		- ThreatActor
//		- Sighting
func OptionLastSeen(t *Timestamp) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "LastSeen", t, reflect.Ptr)
	}
}

// OptionObjective sets the objective attribute. This option is valid for the types:
//		- Campaign
func OptionObjective(o string) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "Objective", o, reflect.String)
	}
}

// OptionName sets the name attribute. This option is valid for the types:
//		- Grouping
//		- Indicator
//		- Location
//		- Malware
//		- AutonomousSystem
//		- MarkingDefinition
func OptionName(n string) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "Name", n, reflect.String)
	}
}

// OptionClass sets the identity class attribute. This option is valid for the types:
//		- Identity
func OptionClass(s string) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "Class", s, reflect.String)
	}
}

// OptionRoles sets the roles attribute. This option is valid for the types:
//		- Identity
//		- ThreatActor
func OptionRoles(s []string) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "Roles", s, reflect.Slice)
	}
}

// OptionSectors sets the sectors attribute. This option is valid for the types:
//		- Identity
func OptionSectors(s []string) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "Sectors", s, reflect.Slice)
	}
}

// OptionContactInformation sets the contact information attribute. This option is valid for the types:
//		- Identity
func OptionContactInformation(s string) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "ContactInformation", s, reflect.String)
	}
}

// OptionTypes sets the indicator types attribute. This option is valid for the types:
//		- Indicator
//		- Infrastructure
//		- Malware
//		- Report
//		- ThreatActor
//		- Tool
func OptionTypes(s []string) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "Types", s, reflect.Slice)
	}
}

// OptionPatternVersion sets the pattern version attribute. This option is valid for the types:
//		- Indicator
func OptionPatternVersion(s string) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "PatternVersion", s, reflect.String)
	}
}

// OptionValidUntil sets the valid until attribute. This option is valid for the types:
//		- Indicator
func OptionValidUntil(t *Timestamp) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "ValidUntil", t, reflect.Ptr)
	}
}

// OptionGoals sets the goals attribute. This option is valid for the types:
//		- IntrusionSet
//		- ThreatActor
func OptionGoals(s []string) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "Goals", s, reflect.Slice)
	}
}

// OptionResourceLevel sets the resource level attribute. This option is valid for the types:
//		- IntrusionSet
//		- ThreatActor
func OptionResourceLevel(s string) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "ResourceLevel", s, reflect.String)
	}
}

// OptionPrimaryMotivation sets the primary motivation attribute. This option is valid for the types:
//		- IntrusionSet
//		- ThreatActor
func OptionPrimaryMotivation(s string) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "PrimaryMotivation", s, reflect.String)
	}
}

// OptionSecondaryMotivations sets the secondary motivation attribute. This option is valid for the types:
//		- IntrusionSet
//		- ThreatActor
func OptionSecondaryMotivations(s []string) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "SecondaryMotivations", s, reflect.Slice)
	}
}

// OptionPrecision sets the precision attribute. This option is valid for the types:
//		- Location
func OptionPrecision(p float64) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "Precision", p, reflect.Float64)
	}
}

// OptionAdministrativeArea sets the administrative area attribute. This option is valid for the types:
//		- Location
func OptionAdministrativeArea(a string) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "AdministrativeArea", a, reflect.String)
	}
}

// OptionCity sets the city attribute. This option is valid for the types:
//		- Location
func OptionCity(c string) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "City", c, reflect.String)
	}
}

// OptionStreetAddress sets the street address attribute. This option is valid for the types:
//		- Location
func OptionStreetAddress(s string) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "StreetAddress", s, reflect.String)
	}
}

// OptionPostalCode sets the postal code attribute. This option is valid for the types:
//		- Location
func OptionPostalCode(s string) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "PostalCode", s, reflect.String)
	}
}

// OptionOperatingSystems sets the OS attribute. This option is valid for the types:
//		- Malware
func OptionOperatingSystems(s []Identifier) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "OperatingSystems", s, reflect.Slice)
	}
}

// OptionArchitecture sets the architecture attribute. This option is valid for the types:
//		- Malware
func OptionArchitecture(s []string) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "Architecture", s, reflect.Slice)
	}
}

// OptionLanguages sets the languages attribute. This option is valid for the types:
//		- Malware
//		- Software
func OptionLanguages(s []string) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "Languages", s, reflect.Slice)
	}
}

// OptionCapabilities sets the capabilities attribute. This option is valid for the types:
//		- Malware
func OptionCapabilities(s []string) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "Capabilities", s, reflect.Slice)
	}
}

// OptionSamples sets the samples attribute. This option is valid for the types:
//		- Malware
func OptionSamples(s []Identifier) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "Samples", s, reflect.Slice)
	}
}

// OptionVersion sets the version attribute. This option is valid for the types:
//		- MalwareAnalysis
//		- Tool
//		- Software
//		- X509Certificate
func OptionVersion(s string) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "Version", s, reflect.String)
	}
}

// OptionHostVM sets the host VM attribute. This option is valid for the types:
//		- MalwareAnalysis
func OptionHostVM(s Identifier) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "HostVM", s, reflect.String)
	}
}

// OptionOperatingSystem sets the OS attribute. This option is valid for the types:
//		- MalwareAnalysis
func OptionOperatingSystem(s Identifier) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "OperatingSystem", s, reflect.String)
	}
}

// OptionInstalledSoftware sets the installed software attribute. This option is valid for the types:
//		- MalwareAnalysis
func OptionInstalledSoftware(s []Identifier) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "InstalledSoftware", s, reflect.Slice)
	}
}

// OptionConfigurationVersion sets the configuration version This option is valid for the types:
//		- MalwareAnalysis
// attribute. This option is valid for the types:
func OptionConfigurationVersion(s string) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "ConfigurationVersion", s, reflect.String)
	}
}

// OptionModules sets the modules attribute. This option is valid for the types:
//		- MalwareAnalysis
func OptionModules(s []string) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "Modules", s, reflect.Slice)
	}
}

// OptionAnalysisEngineVersion sets the analysis engine version
// attribute. This option is valid for the types:
//		- MalwareAnalysis
func OptionAnalysisEngineVersion(s string) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "AnalysisEngineVersion", s, reflect.String)
	}
}

// OptionAnalysisDefinitionVersion sets the analysis definition
// version attribute. This option is valid for the types:
//		- MalwareAnalysis
func OptionAnalysisDefinitionVersion(s string) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "AnalysisDefinitionVersion", s, reflect.String)
	}
}

// OptionSubmitted sets the submitted attribute. This option is valid for the types:
//		- MalwareAnalysis
func OptionSubmitted(s *Timestamp) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "Submitted", s, reflect.Ptr)
	}
}

// OptionAnalysisStarted sets the analysis started attribute. This option is valid for the types:
//		- MalwareAnalysis
func OptionAnalysisStarted(s *Timestamp) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "AnalysisStarted", s, reflect.Ptr)
	}
}

// OptionAnalysisEnded sets the analysis ended attribute. This option is valid for the types:
//		- MalwareAnalysis
func OptionAnalysisEnded(s *Timestamp) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "AnalysisEnded", s, reflect.Ptr)
	}
}

// OptionResultName sets the analysis result name attribute. This option is valid for the types:
//		- MalwareAnalysis
func OptionResultName(s string) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "ResultName", s, reflect.String)
	}
}

// OptionSample sets the analysis sample attribute. This option is valid for the types:
//		- MalwareAnalysis
func OptionSample(s Identifier) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "Sample", s, reflect.String)
	}
}

// OptionAbstract sets the abstract attribute. This option is valid for the types:
//		- Note
func OptionAbstract(s string) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "Abstract", s, reflect.String)
	}
}

// OptionAuthors sets the authors attribute. This option is valid for the types:
//		- Note
//		- Opinion
func OptionAuthors(s []string) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "Authors", s, reflect.Slice)
	}
}

// OptionExplanation sets the explanation attribute. This option is valid for the types:
//		- Opinion
func OptionExplanation(s string) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "Explanation", s, reflect.String)
	}
}

// OptionSophistication sets the sophistication attribute. This option is valid for the types:
//		- ThreatActor
func OptionSophistication(s string) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "Sophistication", s, reflect.String)
	}
}

// OptionPersonalMotivations sets the personal motivations attribute. This option is valid for the types:
//		- ThreatActor
func OptionPersonalMotivations(s []string) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "PersonalMotivations", s, reflect.Slice)
	}
}

// OptionStartTime sets the start time attribute. This option is valid for the types:
//		- Relationship
func OptionStartTime(t *Timestamp) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "StartTime", t, reflect.Ptr)
	}
}

// OptionStopTime sets the stop time attribute. This option is valid for the types:
//		- Relationship
func OptionStopTime(t *Timestamp) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "StopTime", t, reflect.Ptr)
	}
}

// OptionCount sets the count attribute. This option is valid for the types:
//		- Sighting
func OptionCount(c int64) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "Count", c, reflect.Int64)
	}
}

// OptionObservedData sets the ObservedData attribute. This option is valid for the types:
//		- Sighting
func OptionObservedData(d []Identifier) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "ObservedData", d, reflect.Slice)
	}
}

// OptionWhereSighted sets the WhereSighted attribute. This option is valid for the types:
//		- Sighting
func OptionWhereSighted(i []Identifier) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "WhereSighted", i, reflect.Slice)
	}
}

// OptionSummary sets the summary attribute. This option is valid for the types:
//		- Sighting
func OptionSummary(b bool) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "Summary", b, reflect.Bool)
	}
}

// OptionMimeType sets the mime type attribute. This option is valid for the types:
//		- Artifact
//		- File
func OptionMimeType(s string) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "MimeType", s, reflect.String)
	}
}

// OptionPayload sets the payload attribute. This option is valid for the types:
//		- Artifact
func OptionPayload(s Binary) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "Payload", s, reflect.Slice)
	}
}

// OptionURL sets the URL attribute. This option is valid for the types:
//		- Artifact
func OptionURL(s string) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "URL", s, reflect.String)
	}
}

// OptionHashes sets the hashes attribute. This option is valid for the types:
//		- Artifact
//		- File
//		- X509Certificate
func OptionHashes(s Hashes) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "Hashes", s, reflect.Map)
	}
}

// OptionEncryption sets the encryption algorithm attribute. This option is valid for the types:
//		- Artifact
func OptionEncryption(s EncryptionAlgorithm) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "Encryption", s, reflect.Uint8)
	}
}

// OptionKey sets the decryption key attribute. This option is valid for the types:
//		- Artifact
//		- RegistryKey
func OptionKey(s string) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "Key", s, reflect.String)
	}
}

// OptionRIR sets the rir attribute. This option is valid for the types:
//		- AutonomousSystem
func OptionRIR(s string) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "RIR", s, reflect.String)
	}
}

// OptionPathEncoding sets the path encoding attribute. This option is valid for the types:
//		- Directory
func OptionPathEncoding(s string) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "PathEnc", s, reflect.String)
	}
}

// OptionCtime sets the ctime attribute. This option is valid for the types:
//		- Directory
//		- File
func OptionCtime(s *Timestamp) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "Ctime", s, reflect.Ptr)
	}
}

// OptionMtime sets the mtime attribute. This option is valid for the types:
//		- Directory
//		- File
func OptionMtime(s *Timestamp) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "Mtime", s, reflect.Ptr)
	}
}

// OptionAtime sets the atime attribute. This option is valid for the types:
//		- Directory
//		- File
func OptionAtime(s *Timestamp) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "Atime", s, reflect.Ptr)
	}
}

// OptionContains sets the contains attribute. This option is valid for the types:
//		- Directory
//		- File
func OptionContains(s []Identifier) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "Contains", s, reflect.Slice)
	}
}

// OptionResolvesTo sets the resolves to attribute. This option is valid for the types:
//		- DomainName
//		- IPv4Address
//		- IPv6Address
func OptionResolvesTo(s []Identifier) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "ResolvesTo", s, reflect.Slice)
	}
}

// OptionDisplayName sets the display name attribute. This option is valid for the types:
//		- EmailAddress
//		- UserAccount
func OptionDisplayName(s string) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "DisplayName", s, reflect.String)
	}
}

// OptionBelongsTo sets the belongs to attribute. This option is valid for the types:
//		- EmailAddress
//		- IPv4Address
//		- IPv6Address
func OptionBelongsTo(s Identifier) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "BelongsTo", s, reflect.String)
	}
}

// OptionDate sets the date attribute. This option is valid for the types:
//		- EmailMessage
func OptionDate(s *Timestamp) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "Date", s, reflect.Ptr)
	}
}

// OptionContentType sets the content type attribute. This option is valid for the types:
//		- EmailMessage
func OptionContentType(s string) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "ContentType", s, reflect.String)
	}
}

// OptionFrom sets the from attribute. This option is valid for the types:
//		- EmailMessage
func OptionFrom(s Identifier) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "From", s, reflect.String)
	}
}

// OptionSender sets the sender attribute. This option is valid for the types:
//		- EmailMessage
func OptionSender(s Identifier) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "Sender", s, reflect.String)
	}
}

// OptionTo sets the to attribute. This option is valid for the types:
//		- EmailMessage
func OptionTo(s []Identifier) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "To", s, reflect.Slice)
	}
}

// OptionCC sets the CC attribute. This option is valid for the types:
//		- EmailMessage
func OptionCC(s []Identifier) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "CC", s, reflect.Slice)
	}
}

// OptionBCC sets the BCC attribute. This option is valid for the types:
//		- EmailMessage
func OptionBCC(s []Identifier) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "BCC", s, reflect.Slice)
	}
}

// OptionMessageID sets the message ID attribute. This option is valid for the types:
//		- EmailMessage
func OptionMessageID(s string) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "MessageID", s, reflect.String)
	}
}

// OptionSubject sets the subject attribute. This option is valid for the types:
//		- EmailMessage
func OptionSubject(s string) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "Subject", s, reflect.String)
	}
}

// OptionReceivedLines sets the received lines attribute. This option is valid for the types:
//		- EmailMessage
func OptionReceivedLines(s []string) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "ReceivedLines", s, reflect.Slice)
	}
}

// OptionAdditionalHeaderFields sets the additional header fields
// attribute. This option is valid for the types:
//		- EmailMessage
func OptionAdditionalHeaderFields(s map[string]string) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "AdditionalHeaderFields", s, reflect.Map)
	}
}

// OptionBody sets the body attribute. This option is valid for the types:
//		- EmailMessage
func OptionBody(s string) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "Body", s, reflect.String)
	}
}

// OptionBodyMultipart sets the body multipart attribute. This option is valid for the types:
//		- EmailMessage
func OptionBodyMultipart(s []EmailMIME) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "BodyMultipart", s, reflect.Slice)
	}
}

// OptionRawEmail sets the raw email attribute. This option is valid for the types:
//		- EmailMessage
func OptionRawEmail(s Identifier) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "RawEmail", s, reflect.String)
	}
}

// OptionSize sets the size attribute. This option is valid for the types:
//		- File
func OptionSize(s int64) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "Size", s, reflect.Int64)
	}
}

// OptionNameEnc sets the name encoding attribute. This option is valid for the types:
//		- File
func OptionNameEnc(s string) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "NameEnc", s, reflect.String)
	}
}

// OptionMagicNumber sets the magic number attribute. This option is valid for the types:
//		- File
func OptionMagicNumber(s Hex) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "MagicNumber", s, reflect.String)
	}
}

// OptionParentDirectory sets the parent directory attribute. This option is valid for the types:
//		- File
func OptionParentDirectory(s Identifier) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "ParentDirectory", s, reflect.String)
	}
}

// OptionContent sets the content attribute. This option is valid for the types:
//		- File
func OptionContent(s Identifier) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "Content", s, reflect.String)
	}
}

// OptionStart sets the start attribute. This option is valid for the types:
//		- NetworkTraffic
func OptionStart(s *Timestamp) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "Start", s, reflect.Ptr)
	}
}

// OptionEnd sets the end attribute. This option is valid for the types:
//		- NetworkTraffic
func OptionEnd(s *Timestamp) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "End", s, reflect.Ptr)
	}
}

// OptionIsActive sets the is active attribute. This option is valid for the types:
//		- NetworkTraffic
func OptionIsActive(s bool) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "IsActive", s, reflect.Bool)
	}
}

// OptionSrc sets the src attribute. This option is valid for the types:
//		- NetworkTraffic
func OptionSrc(s Identifier) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "Src", s, reflect.String)
	}
}

// OptionDst sets the dst attribute. This option is valid for the types:
//		- NetworkTraffic
func OptionDst(s Identifier) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "Dst", s, reflect.String)
	}
}

// OptionSrcPort sets the src port attribute. This option is valid for the types:
//		- NetworkTraffic
func OptionSrcPort(s int64) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "SrcPort", s, reflect.Int64)
	}
}

// OptionDstPort sets the dst port attribute. This option is valid for the types:
//		- NetworkTraffic
func OptionDstPort(s int64) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "DstPort", s, reflect.Int64)
	}
}

// OptionSrcByteCount sets the src byte count attribute. This option is valid for the types:
//		- NetworkTraffic
func OptionSrcByteCount(s int64) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "SrcByteCount", s, reflect.Int64)
	}
}

// OptionDstByteCount sets the dst byte count attribute. This option is valid for the types:
//		- NetworkTraffic
func OptionDstByteCount(s int64) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "DstByteCount", s, reflect.Int64)
	}
}

// OptionSrcPackets sets the src packets attribute. This option is valid for the types:
//		- NetworkTraffic
func OptionSrcPackets(s int64) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "SrcPackets", s, reflect.Int64)
	}
}

// OptionDstPackets sets the dst packets attribute. This option is valid for the types:
//		- NetworkTraffic
func OptionDstPackets(s int64) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "DstPackets", s, reflect.Int64)
	}
}

// OptionIPFIX sets the IPFIX attribute. This option is valid for the types:
//		- NetworkTraffic
func OptionIPFIX(s map[string]interface{}) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "IPFIX", s, reflect.Map)
	}
}

// OptionSrcPayload sets the src payload attribute. This option is valid for the types:
//		- NetworkTraffic
func OptionSrcPayload(s Identifier) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "SrcPayload", s, reflect.String)
	}
}

// OptionDstPayload sets the src payload attribute. This option is valid for the types:
//		- NetworkTraffic
func OptionDstPayload(s Identifier) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "DstPayload", s, reflect.String)
	}
}

// OptionEncapsulates sets the encapsulates attribute. This option is valid for the types:
//		- NetworkTraffic
func OptionEncapsulates(s []Identifier) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "Encapsulates", s, reflect.Slice)
	}
}

// OptionEncapsulated sets the encapsulated attribute. This option is valid for the types:
//		- NetworkTraffic
func OptionEncapsulated(s Identifier) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "Encapsulated", s, reflect.String)
	}
}

// OptionIsHidden sets the is hidden attribute. This option is valid for the types:
//		- Process
func OptionIsHidden(s bool) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "IsHidden", s, reflect.Bool)
	}
}

// OptionPID sets the PID attribute. This option is valid for the types:
//		- Process
func OptionPID(s int64) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "PID", s, reflect.Int64)
	}
}

// OptionCreatedTime sets the created time attribute. This option is valid for the types:
//		- Process
func OptionCreatedTime(s *Timestamp) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "CreatedTime", s, reflect.Ptr)
	}
}

// OptionCwd sets the cwd attribute. This option is valid for the types:
//		- Process
func OptionCwd(s string) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "Cwd", s, reflect.String)
	}
}

// OptionCommandLine sets the command line attribute. This option is valid for the types:
//		- Process
func OptionCommandLine(s string) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "CommandLine", s, reflect.String)
	}
}

// OptionEnvVars sets the environment variables attribute. This option is valid for the types:
//		- Process
func OptionEnvVars(s map[string]string) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "EnvVars", s, reflect.Map)
	}
}

// OptionOpenedConnections sets the opened connections attribute. This option is valid for the types:
//		- Process
func OptionOpenedConnections(s []Identifier) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "OpenedConnections", s, reflect.Slice)
	}
}

// OptionCreatorUser sets the creator user attribute. This option is valid for the types:
//		- Process
//		- RegistryKey
func OptionCreatorUser(s Identifier) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "CreatorUser", s, reflect.String)
	}
}

// OptionImage sets the image attribute. This option is valid for the types:
//		- Process
func OptionImage(s Identifier) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "Image", s, reflect.String)
	}
}

// OptionParent sets the parent attribute. This option is valid for the types:
//		- Process
func OptionParent(s Identifier) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "Parent", s, reflect.String)
	}
}

// OptionChild sets the child attribute. This option is valid for the types:
//		- Process
func OptionChild(s []Identifier) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "Child", s, reflect.Slice)
	}
}

// OptionCPE sets the CPE attribute. This option is valid for the types:
//		- Software
func OptionCPE(s string) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "CPE", s, reflect.String)
	}
}

// OptionSWID sets the SWID attribute. This option is valid for the types:
//		- Software
func OptionSWID(s string) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "SWID", s, reflect.String)
	}
}

// OptionVendor sets the vendor attribute. This option is valid for the types:
//		- Software
func OptionVendor(s string) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "Vendor", s, reflect.String)
	}
}

// OptionUserID sets the user id attribute. This option is valid for the types:
//		- Software
func OptionUserID(s string) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "UserID", s, reflect.String)
	}
}

// OptionCredential sets the credential attribute. This option is valid for the types:
func OptionCredential(s string) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "Credential", s, reflect.String)
	}
}

// OptionAccountLogin sets the account login attribute. This option is valid for the types:
//		- UserAccount
func OptionAccountLogin(s string) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "AccountLogin", s, reflect.String)
	}
}

// OptionAccountType sets the account type attribute. This option is valid for the types:
//		- UserAccount
func OptionAccountType(s string) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "AccountType", s, reflect.String)
	}
}

// OptionIsServiceAccount sets the is service account attribute. This option is valid for the types:
//		- UserAccount
func OptionIsServiceAccount(s bool) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "IsServiceAccount", s, reflect.Bool)
	}
}

// OptionIsPrivileged sets the is privileged attribute. This option is valid for the types:
//		- UserAccount
func OptionIsPrivileged(s bool) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "IsPrivileged", s, reflect.Bool)
	}
}

// OptionCanEscalatePrivs sets the can escalate privs attribute. This option is valid for the types:
//		- UserAccount
func OptionCanEscalatePrivs(s bool) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "CanEscalatePrivs", s, reflect.Bool)
	}
}

// OptionIsDisabled sets the is disabled attribute. This option is valid for the types:
//		- UserAccount
func OptionIsDisabled(s bool) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "IsDisabled", s, reflect.Bool)
	}
}

// OptionAccountCreated sets the account created attribute. This option is valid for the types:
//		- UserAccount
func OptionAccountCreated(s *Timestamp) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "AccountCreated", s, reflect.Ptr)
	}
}

// OptionAccountExpires sets the account expires attribute. This option is valid for the types:
//		- UserAccount
func OptionAccountExpires(s *Timestamp) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "AccountExpires", s, reflect.Ptr)
	}
}

// OptionCredentialLastChanged sets the credential last changed
// attribute. This option is valid for the types:
//		- UserAccount
func OptionCredentialLastChanged(s *Timestamp) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "CredentialLastChanged", s, reflect.Ptr)
	}
}

// OptionAccountFirstLogin sets the account first login attribute. This option is valid for the types:
//		- UserAccount
func OptionAccountFirstLogin(s *Timestamp) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "AccountFirstLogin", s, reflect.Ptr)
	}
}

// OptionAccountLastLogin sets the account last login attribute. This option is valid for the types:
//		- UserAccount
func OptionAccountLastLogin(s *Timestamp) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "AccountLastLogin", s, reflect.Ptr)
	}
}

// OptionValues sets the values attribute. This option is valid for the types:
//		- RegistryKey
func OptionValues(s []*RegistryValue) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "Values", s, reflect.Slice)
	}
}

// OptionModifiedTime sets the modified time attribute. This option is valid for the types:
//		- RegistryKey
func OptionModifiedTime(s *Timestamp) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "ModifiedTime", s, reflect.Ptr)
	}
}

// OptionNumberOfSubkeys sets the number of subkeys attribute. This option is valid for the types:
//		- RegistryKey
func OptionNumberOfSubkeys(s int64) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "NumberOfSubkeys", s, reflect.Int64)
	}
}

// OptionSelfSigned sets the self-signed attribute. This option is valid for the types:
//		- X509Certificate
func OptionSelfSigned(s bool) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "SelfSigned", s, reflect.Bool)
	}
}

// OptionSerialNumber sets the serial number attribute. This option is valid for the types:
//		- X509Certificate
func OptionSerialNumber(s string) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "SerialNumber", s, reflect.String)
	}
}

// OptionSignatureAlgorithm sets the signature algorithm attribute. This option is valid for the types:
//		- X509Certificate
func OptionSignatureAlgorithm(s string) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "SignatureAlgorithm", s, reflect.String)
	}
}

// OptionIssuer sets the issuer attribute. This option is valid for the types:
//		- X509Certificate
func OptionIssuer(s string) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "Issuer", s, reflect.String)
	}
}

// OptionValidityNotBefore sets the validity not before
// attribute. This option is valid for the types:
//		- X509Certificate
func OptionValidityNotBefore(s *Timestamp) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "ValidityNotBefore", s, reflect.Ptr)
	}
}

// OptionValidityNotAfter sets the validity not after
// attribute. This option is valid for the types:
//		- X509Certificate
func OptionValidityNotAfter(s *Timestamp) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "ValidityNotAfter", s, reflect.Ptr)
	}
}

// OptionSubjectPublicKeyAlgorithm sets the subject public key
// algorithm attribute. This option is valid for the types:
//		- X509Certificate
func OptionSubjectPublicKeyAlgorithm(s string) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "SubjectPublicKeyAlghorithm", s, reflect.String)
	}
}

// OptionSubjectPublicKeyModulus sets the subject public key
// modulus attribute. This option is valid for the types:
//		- X509Certificate
func OptionSubjectPublicKeyModulus(s string) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "SubjectPublicKeyModulus", s, reflect.String)
	}
}

// OptionSubjectPublicKeyExponent sets the subject public key
// exponent attribute. This option is valid for the types:
//		- X509Certificate
func OptionSubjectPublicKeyExponent(s int64) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "SubjectPublicKeyExponent", s, reflect.Int64)
	}
}

// OptionV3Extensions sets the x.509v3 extensions attribute. This option is valid for the types:
//		- X509Certificate
func OptionV3Extensions(s X509v3Extension) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "X509v3Extensions", s, reflect.Struct)
	}
}

// OptionObjectModified sets the object modified attribute. This option is valid for the types:
//		- LanguageContent
func OptionObjectModified(s *Timestamp) STIXOption {
	return func(obj StixObject) error {
		return setField(obj, "ObjectModified", s, reflect.Ptr)
	}
}

/*
	Helper functions
*/

func applyOptions(obj StixObject, opts []STIXOption) error {
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(obj); err != nil {
			return err
		}
	}
	return nil
}

func setField(obj StixObject, field string, value interface{}, kind reflect.Kind) error {
	val, err := reflectValue(obj)
	if err != nil {
		return err
	}

	f, err := getFieldFromBaseStruct(val, field)
	if err != nil {
		return fmt.Errorf("failed to apply %s option: %w", field, err)
	}

	if f.Kind() != kind {
		return fmt.Errorf("%s field is not a %s type", kind, field)
	}

	f.Set(reflect.ValueOf(value))
	return nil
}

func reflectValue(obj StixObject) (reflect.Value, error) {
	val := reflect.ValueOf(obj)

	// Check the type.

	if val.Kind() != reflect.Ptr {
		return reflect.Value{}, fmt.Errorf("object must be a pointer type")
	}

	val = val.Elem()

	if val.Kind() != reflect.Struct {
		return reflect.Value{}, fmt.Errorf("object has to be a pointer to struct")
	}

	return val, nil
}

var baseStructs = []string{"STIXCyberObservableObject", "STIXDomainObject"}

func getFieldFromBaseStruct(obj reflect.Value, field string) (reflect.Value, error) {
	// First check in base structs.
	for _, baseString := range baseStructs {
		b := obj.FieldByName(baseString)
		if !b.IsValid() {
			continue
		}

		if b.Kind() != reflect.Struct {
			return reflect.Value{}, fmt.Errorf("%s is not of struct type", baseString)
		}

		f := b.FieldByName(field)
		if f.IsValid() && f.CanSet() {
			return f, nil
		}
	}

	// If not in the base struct, check the main struct.
	f := obj.FieldByName(field)
	if f.IsValid() && f.CanSet() {
		return f, nil
	}

	return reflect.Value{}, fmt.Errorf("%s not found", field)
}
