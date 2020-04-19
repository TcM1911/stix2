// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import "fmt"

// MACAddress represents a single Media Access Control (MAC) address.
type MACAddress struct {
	STIXCyberObservableObject
	// Value specifies the value of a single MAC address.
	Value string `json:"value"`
}

// NewMACAddress creates a new MACAddress object.
func NewMACAddress(value string, opts ...MACAddressOption) (*MACAddress, error) {
	if value == "" {
		return nil, ErrInvalidParameter
	}
	base := newSTIXCyberObservableObject(TypeMACAddress)
	obj := &MACAddress{
		STIXCyberObservableObject: base,
		Value:                     value,
	}

	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(obj)
	}
	obj.ID = NewObservableIdenfier(fmt.Sprintf("[\"%s\"]", value), TypeMACAddress)
	return obj, nil
}

// MACAddressOption is an optional parameter when constructing a
// MACAddress object.
type MACAddressOption func(a *MACAddress)

/*
	Base object options
*/

// MACAddressOptionSpecVersion sets the STIX spec version.
func MACAddressOptionSpecVersion(ver string) MACAddressOption {
	return func(obj *MACAddress) {
		obj.SpecVersion = ver
	}
}

// MACAddressOptionObjectMarking sets the object marking attribute.
func MACAddressOptionObjectMarking(om []Identifier) MACAddressOption {
	return func(obj *MACAddress) {
		obj.ObjectMarking = om
	}
}

// MACAddressOptionGranularMarking sets the granular marking attribute.
func MACAddressOptionGranularMarking(gm []*GranularMarking) MACAddressOption {
	return func(obj *MACAddress) {
		obj.GranularMarking = gm
	}
}

// MACAddressOptionDefanged sets the defanged attribute.
func MACAddressOptionDefanged(b bool) MACAddressOption {
	return func(obj *MACAddress) {
		obj.Defanged = b
	}
}

// MACAddressOptionExtension adds an extension.
func MACAddressOptionExtension(name string, value interface{}) MACAddressOption {
	return func(obj *MACAddress) {
		// Ignoring the error.
		obj.addExtension(name, value)
	}
}
