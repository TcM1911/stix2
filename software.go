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
	// SWID specifies the Software Identification (SWID) Tags entry for the
	// software, if available. The tag attribute, tagId, a globally unique
	// identifier, SHOULD be used as a proxy identifier of the tagged product.
	SWID string `json:"swid,omitempty"`
	// Languages specifies the languages supported by the software. The value
	// of each list member MUST be an ISO 639-2 language code.
	Languages []string `json:"languages,omitempty"`
	// Vendor specifies the name of the vendor of the software.
	Vendor string `json:"vendor,omitempty"`
	// Version specifies the version of the software.
	Version string `json:"version,omitempty"`
}

func (o *Software) MarshalJSON() ([]byte, error) {
	return marshalToJSONHelper(o)
}

// NewSoftware creates a new Software object. A Software object MUST contain at least one
// of hashes or name.
func NewSoftware(name string, opts ...STIXOption) (*Software, error) {
	if name == "" {
		return nil, ErrInvalidParameter
	}
	base := newSTIXCyberObservableObject(TypeSoftware)
	obj := &Software{
		STIXCyberObservableObject: base,
		Name:                      name,
	}

	err := applyOptions(obj, opts)
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
	obj.ID = NewObservableIdentifier(fmt.Sprintf("[%s]", strings.Join(idContri, ",")), TypeSoftware)
	return obj, err
}
