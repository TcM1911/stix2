// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import "fmt"

// URL object represents the properties of a uniform resource locator (URL).
type URL struct {
	STIXCyberObservableObject
	// Value specifies the value of the URL. The value of this property MUST
	// conform to RFC3986, more specifically section 1.1.3 with reference to
	// the definition for "Uniform Resource Locator".
	Value string `json:"value"`
}

// NewURL creates a new URL object.
func NewURL(value string, opts ...STIXOption) (*URL, error) {
	if value == "" {
		return nil, ErrInvalidParameter
	}
	base := newSTIXCyberObservableObject(TypeURL)
	obj := &URL{
		STIXCyberObservableObject: base,
		Value:                     value,
	}

	err := applyOptions(obj, opts)
	obj.ID = NewObservableIdentifier(fmt.Sprintf("[\"%s\"]", value), TypeURL)
	return obj, err
}
