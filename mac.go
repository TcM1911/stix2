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

func (o *MACAddress) MarshalJSON() ([]byte, error) {
	return marshalToJSONHelper(o)
}

// NewMACAddress creates a new MACAddress object.
func NewMACAddress(value string, opts ...STIXOption) (*MACAddress, error) {
	if value == "" {
		return nil, ErrInvalidParameter
	}
	base := newSTIXCyberObservableObject(TypeMACAddress)
	obj := &MACAddress{
		STIXCyberObservableObject: base,
		Value:                     value,
	}

	err := applyOptions(obj, opts)
	obj.ID = NewObservableIdentifier(fmt.Sprintf("[\"%s\"]", value), TypeMACAddress)
	return obj, err
}
