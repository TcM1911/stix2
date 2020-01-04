// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import "fmt"

// URL object represents the properties of a uniform resource locator (URL).
type URL struct {
	*STIXCyberObservableObject
	// Value specifies the value of the URL. The value of this property MUST
	// conform to RFC3986, more specifically section 1.1.3 with reference to
	// the definition for "Uniform Resource Locator".
	Value string `json:"value"`
}

// NewURL creates a new URL object.
func NewURL(value string, opts ...URLOption) (*URL, error) {
	if value == "" {
		return nil, ErrInvalidParameter
	}
	base := newSTIXCyberObservableObject(TypeURL)
	obj := &URL{
		STIXCyberObservableObject: base,
		Value:                     value,
	}

	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(obj)
	}
	obj.ID = NewObservableIdenfier(fmt.Sprintf("[\"%s\"]", value), TypeURL)
	return obj, nil
}

// URLOption is an optional parameter when constructing a
// URL object.
type URLOption func(a *URL)

/*
	Base object options
*/

// URLOptionSpecVersion sets the STIX spec version.
func URLOptionSpecVersion(ver string) URLOption {
	return func(obj *URL) {
		obj.SpecVersion = ver
	}
}

// URLOptionObjectMarking sets the object marking attribute.
func URLOptionObjectMarking(om []Identifier) URLOption {
	return func(obj *URL) {
		obj.ObjectMarking = om
	}
}

// URLOptionGranularMarking sets the granular marking attribute.
func URLOptionGranularMarking(gm *GranularMarking) URLOption {
	return func(obj *URL) {
		obj.GranularMarking = gm
	}
}

// URLOptionDefanged sets the defanged attribute.
func URLOptionDefanged(b bool) URLOption {
	return func(obj *URL) {
		obj.Defanged = b
	}
}

// URLOptionExtension adds an extension.
func URLOptionExtension(name string, value interface{}) URLOption {
	return func(obj *URL) {
		// Ignoring the error.
		obj.addExtension(name, value)
	}
}
