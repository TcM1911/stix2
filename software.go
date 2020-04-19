// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import (
	"fmt"
	"strings"
)

// Software object represents high-level properties associated with software,
// including software products.
type Software struct {
	STIXCyberObservableObject
	// Name specifies the name of the software.
	Name string `json:"name"`
	// CPE specifies the Common Platform Enumeration (CPE) entry for the
	// software, if available. The value for this property MUST be a CPE v2.3
	// entry from the official NVD CPE Dictionary.
	CPE string `json:"cpe,omitempty"`
	// Languages specifies the languages supported by the software. The value
	// of each list member MUST be an ISO 639-2 language code.
	Languages []string `json:"languages,omitempty"`
	// Vendor specifies the name of the vendor of the software.
	Vendor string `json:"vendor,omitempty"`
	// Version specifies the version of the software.
	Version string `json:"version,omitempty"`
}

// NewSoftware creates a new Software object. A Software object MUST contain at least one
// of hashes or name.
func NewSoftware(name string, opts ...SoftwareOption) (*Software, error) {
	if name == "" {
		return nil, ErrInvalidParameter
	}
	base := newSTIXCyberObservableObject(TypeSoftware)
	obj := &Software{
		STIXCyberObservableObject: base,
		Name:                      name,
	}

	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(obj)
	}
	idContri := make([]string, 0, 4)
	idContri = append(idContri, fmt.Sprintf(`"%s"`, obj.Name))
	if obj.CPE != "" {
		idContri = append(idContri, fmt.Sprintf(`"%s"`, obj.CPE))
	}
	if obj.Vendor != "" {
		idContri = append(idContri, fmt.Sprintf(`"%s"`, obj.Vendor))
	}
	if obj.Version != "" {
		idContri = append(idContri, fmt.Sprintf(`"%s"`, obj.Version))
	}
	obj.ID = NewObservableIdenfier(fmt.Sprintf("[%s]", strings.Join(idContri, ",")), TypeSoftware)
	return obj, nil
}

// SoftwareOption is an optional parameter when constructing a
// Software object.
type SoftwareOption func(a *Software)

/*
	Base object options
*/

// SoftwareOptionSpecVersion sets the STIX spec version.
func SoftwareOptionSpecVersion(ver string) SoftwareOption {
	return func(obj *Software) {
		obj.SpecVersion = ver
	}
}

// SoftwareOptionObjectMarking sets the object marking attribute.
func SoftwareOptionObjectMarking(om []Identifier) SoftwareOption {
	return func(obj *Software) {
		obj.ObjectMarking = om
	}
}

// SoftwareOptionGranularMarking sets the granular marking attribute.
func SoftwareOptionGranularMarking(gm []*GranularMarking) SoftwareOption {
	return func(obj *Software) {
		obj.GranularMarking = gm
	}
}

// SoftwareOptionDefanged sets the defanged attribute.
func SoftwareOptionDefanged(b bool) SoftwareOption {
	return func(obj *Software) {
		obj.Defanged = b
	}
}

// SoftwareOptionExtension adds an extension.
func SoftwareOptionExtension(name string, value interface{}) SoftwareOption {
	return func(obj *Software) {
		// Ignoring the error.
		obj.addExtension(name, value)
	}
}

/*
	Software object options
*/

// SoftwareOptionCPE sets the CPE attribute.
func SoftwareOptionCPE(s string) SoftwareOption {
	return func(obj *Software) {
		obj.CPE = s
	}
}

// SoftwareOptionLanguages sets the languages attribute.
func SoftwareOptionLanguages(s []string) SoftwareOption {
	return func(obj *Software) {
		obj.Languages = s
	}
}

// SoftwareOptionVendor sets the vendor attribute.
func SoftwareOptionVendor(s string) SoftwareOption {
	return func(obj *Software) {
		obj.Vendor = s
	}
}

// SoftwareOptionVersion sets the version attribute.
func SoftwareOptionVersion(s string) SoftwareOption {
	return func(obj *Software) {
		obj.Version = s
	}
}
