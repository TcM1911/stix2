// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import (
	"fmt"
	"strings"
)

// RegistryKey object represents the properties of a Windows registry key. As
// all properties of this object are optional, at least one of the properties
// defined below MUST be included when using this object.
type RegistryKey struct {
	*STIXCyberObservableObject
	// Key specifies the full registry key including the hive. The value of the
	// key, including the hive portion, SHOULD be case-preserved. The hive
	// portion of the key MUST be fully expanded and not truncated; e.g.,
	// HKEY_LOCAL_MACHINE must be used instead of HKLM.
	Key string `json:"key,omitempty"`
	// Values specifies the values found under the registry key.
	Values []*RegistryValue `json:"values,omitempty"`
	// ModifiedTime specifies the last date/time that the registry key was
	// modified.
	ModifiedTime *Timestamp `json:"modified_time,omitempty"`
	// CreatorUser specifies a reference to the user account that created the
	// registry key.
	CreatorUser Identifier `json:"creator_user_ref,omitempty"`
	// NumberOfSubkeys specifies the number of subkeys contained under the
	// registry key.
	NumberOfSubkeys int64 `json:"number_of_subkeys,omitempty"`
}

// NewRegistryKey creates a new RegistryKey object.
func NewRegistryKey(opts ...RegistryKeyOption) (*RegistryKey, error) {
	if len(opts) == 0 {
		return nil, ErrPropertyMissing
	}
	base := newSTIXCyberObservableObject(TypeRegistryKey)
	obj := &RegistryKey{
		STIXCyberObservableObject: base,
	}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(obj)
	}

	idContri := make([]string, 0, 2)
	if obj.Key != "" {
		idContri = append(idContri, fmt.Sprintf(`"%s"`, obj.Key))
	}
	if len(obj.Values) > 0 {
		a := make([]string, 0, len(obj.Values))
		for _, v := range obj.Values {
			a = append(a, v.getIDContrib())
		}
		idContri = append(idContri, fmt.Sprintf(`%s`, strings.Join(a, ",")))
	}
	obj.ID = NewObservableIdenfier(fmt.Sprintf("[%s]", strings.Join(idContri, ",")), TypeRegistryKey)
	return obj, nil
}

// RegistryKeyOption is an optional parameter when constructing a
// RegistryKey object.
type RegistryKeyOption func(a *RegistryKey)

/*
	Base object options
*/

// RegistryKeyOptionSpecVersion sets the STIX spec version.
func RegistryKeyOptionSpecVersion(ver string) RegistryKeyOption {
	return func(obj *RegistryKey) {
		obj.SpecVersion = ver
	}
}

// RegistryKeyOptionObjectMarking sets the object marking attribute.
func RegistryKeyOptionObjectMarking(om []Identifier) RegistryKeyOption {
	return func(obj *RegistryKey) {
		obj.ObjectMarking = om
	}
}

// RegistryKeyOptionGranularMarking sets the granular marking attribute.
func RegistryKeyOptionGranularMarking(gm *GranularMarking) RegistryKeyOption {
	return func(obj *RegistryKey) {
		obj.GranularMarking = gm
	}
}

// RegistryKeyOptionDefanged sets the defanged attribute.
func RegistryKeyOptionDefanged(b bool) RegistryKeyOption {
	return func(obj *RegistryKey) {
		obj.Defanged = b
	}
}

// RegistryKeyOptionExtension adds an extension.
func RegistryKeyOptionExtension(name string, value interface{}) RegistryKeyOption {
	return func(obj *RegistryKey) {
		// Ignoring the error.
		obj.addExtension(name, value)
	}
}

/*
	RegistryKey object options
*/

// RegistryKeyOptionKey sets the key attribute.
func RegistryKeyOptionKey(s string) RegistryKeyOption {
	return func(obj *RegistryKey) {
		obj.Key = s
	}
}

// RegistryKeyOptionValues sets the values attribute.
func RegistryKeyOptionValues(s []*RegistryValue) RegistryKeyOption {
	return func(obj *RegistryKey) {
		obj.Values = s
	}
}

// RegistryKeyOptionModifiedTime sets the modified time attribute.
func RegistryKeyOptionModifiedTime(s *Timestamp) RegistryKeyOption {
	return func(obj *RegistryKey) {
		obj.ModifiedTime = s
	}
}

// RegistryKeyOptionCreatorUser sets the creator user attribute.
func RegistryKeyOptionCreatorUser(s Identifier) RegistryKeyOption {
	return func(obj *RegistryKey) {
		obj.CreatorUser = s
	}
}

// RegistryKeyOptionNumberOfSubkeys sets the number of subkeys attribute.
func RegistryKeyOptionNumberOfSubkeys(s int64) RegistryKeyOption {
	return func(obj *RegistryKey) {
		obj.NumberOfSubkeys = s
	}
}

// RegistryValue captures the properties of a Windows Registry Key Value. As
// all properties of this type are optional, at least one of the properties
// defined below MUST be included when using this type.
type RegistryValue struct {
	// Name specifies the name of the registry value. For specifying the
	// default value in a registry key, an empty string MUST be used.
	Name string `json:"name,omitempty"`
	// Data specifies the data contained in the registry value.
	Data string `json:"data,omitempty"`
	// DataType specifies the registry (REG_*) data type used in the registry
	// value.
	DataType RegistryDataType `json:"data_type,omitempty"`
}

func (r *RegistryValue) getIDContrib() string {
	a := make([]string, 0, 3)
	if r.Data != "" {
		a = append(a, fmt.Sprintf(`"data":"%s"`, r.Data))
	}
	if r.DataType != RegUnknownValue {
		a = append(a, fmt.Sprintf(`"data_type":"%s"`, r.DataType.String()))
	}
	if r.Name != "" {
		a = append(a, fmt.Sprintf(`"name":"%s"`, r.Name))
	}
	return "{" + strings.Join(a, ",") + "}"
}

// RegistryDataType is a type of registry data type.
type RegistryDataType byte

// String returns the string representation of the type.
func (r RegistryDataType) String() string {
	return regDataTypeMap[r]
}

// MarshalJSON serializes the value to JSON.
func (r RegistryDataType) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`"%s"`, r.String())), nil
}

// UnmarshalJSON deserializes the type from the json data.
func (r *RegistryDataType) UnmarshalJSON(b []byte) error {
	if len(b) < 3 {
		*r = RegUnknownValue
		return nil
	}
	t := string(b[1 : len(b)-1])
	for k, v := range regDataTypeMap {
		if v == t {
			*r = k
			return nil
		}
	}
	*r = RegUnknownValue
	return nil
}

const (
	// RegUnknownValue is used for unknown type values.
	RegUnknownValue RegistryDataType = iota
	// RegNone is a no defined value type.
	RegNone
	// RegSz is a null-terminated string. This will be either a Unicode or an
	// ANSI string, depending on whether you use the Unicode or ANSI functions.
	RegSz
	// RegExpandSz is a null-terminated string that contains unexpanded
	// references to environment variables (for example, "%PATH%"). It will be
	// a Unicode or ANSI string depending on whether you use the Unicode or
	// ANSI functions.
	RegExpandSz
	// RegBinary is binary data in any form.
	RegBinary
	// RegDword is a 32-bit number.
	RegDword
	// RegDwordBigEndian is a 32-bit number in big-endian format.
	RegDwordBigEndian
	// RegDwordLittleEndian is a 32-bit number in little-endian format.
	RegDwordLittleEndian
	// RegLink is a null-terminated Unicode string that contains the target
	// path of a symbolic link.
	RegLink
	// RegMultiSz is a sequence of null-terminated strings, terminated by an
	// empty string (\0).
	RegMultiSz
	// RegResourceList is a series of nested lists designed to store a resource
	// list used by a hardware device driver or one of the physical devices it
	// controls. This data is detected and written into the ResourceMap tree by
	// the system and is displayed in Registry Editor in hexadecimal format as
	// a Binary Value.
	RegResourceList
	// RegFullResourceDescription is a series of nested lists designed to store
	// a resource list used by a physical hardware device. This data is
	// detected and written into the HardwareDescription tree by the system and
	// is displayed in Registry Editor in hexadecimal format as a Binary Value.
	RegFullResourceDescription
	// RegResourceRequirementsList is a device driver list of hardware resource
	// requirements in Resource Map tree.
	RegResourceRequirementsList
	// RegQword is a 64-bit number.
	RegQword
	// RegInvalidType specifies an invalid key.
	RegInvalidType
)

var regDataTypeMap = map[RegistryDataType]string{
	RegUnknownValue:             "",
	RegNone:                     "REG_NONE",
	RegSz:                       "REG_SZ",
	RegExpandSz:                 "REG_EXPAND_SZ",
	RegBinary:                   "REG_BINARY",
	RegDword:                    "REG_DWORD",
	RegDwordBigEndian:           "REG_DWORD_BIG_ENDIAN",
	RegDwordLittleEndian:        "REG_DWORD_LITTLE_ENDIAN",
	RegLink:                     "REG_LINK",
	RegMultiSz:                  "REG_MULTI_SZ",
	RegResourceList:             "REG_RESOURCE_LIST",
	RegFullResourceDescription:  "REG_FULL_RESOURCE_DESCRIPTION",
	RegResourceRequirementsList: "REG_RESOURCE_REQUIREMENTS_LIST",
	RegQword:                    "REG_QWORD",
	RegInvalidType:              "REG_INVALID_TYPE",
}
