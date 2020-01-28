// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import "fmt"

// AS object represents the properties of an Autonomous System (AS).
type AS struct {
	STIXCyberObservableObject
	// Number specifies the number assigned to the AS. Such assignments are
	// typically performed by a Regional Internet Registry (RIR).
	Number int64 `json:"number"`
	// Name specifies the name of the AS.
	Name string `json:"name,omitempty"`
	// RIR specifies the name of the Regional Internet Registry (RIR) that
	// assigned the number to the AS.
	RIR string `json:"rir,omitempty"`
}

// NewAS creates a new AS object.
func NewAS(number int64, opts ...ASOption) (*AS, error) {
	if number == 0 {
		return nil, ErrInvalidParameter
	}
	base := newSTIXCyberObservableObject(TypeAS)
	obj := &AS{
		STIXCyberObservableObject: base,
		Number:                    number,
	}

	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(obj)
	}
	obj.ID = NewObservableIdenfier(fmt.Sprintf("[%d]", number), TypeAS)
	return obj, nil
}

// ASOption is an optional parameter when constructing a
// AS object.
type ASOption func(a *AS)

/*
	Base object options
*/

// ASOptionSpecVersion sets the STIX spec version.
func ASOptionSpecVersion(ver string) ASOption {
	return func(obj *AS) {
		obj.SpecVersion = ver
	}
}

// ASOptionObjectMarking sets the object marking attribute.
func ASOptionObjectMarking(om []Identifier) ASOption {
	return func(obj *AS) {
		obj.ObjectMarking = om
	}
}

// ASOptionGranularMarking sets the granular marking attribute.
func ASOptionGranularMarking(gm *GranularMarking) ASOption {
	return func(obj *AS) {
		obj.GranularMarking = gm
	}
}

// ASOptionDefanged sets the defanged attribute.
func ASOptionDefanged(b bool) ASOption {
	return func(obj *AS) {
		obj.Defanged = b
	}
}

// ASOptionExtension adds an extension.
func ASOptionExtension(name string, value interface{}) ASOption {
	return func(obj *AS) {
		// Ignoring the error.
		obj.addExtension(name, value)
	}
}

/*
	AS object options
*/

// ASOptionName sets the name type attribute.
func ASOptionName(s string) ASOption {
	return func(obj *AS) {
		obj.Name = s
	}
}

// ASOptionRIR sets the rir attribute.
func ASOptionRIR(s string) ASOption {
	return func(obj *AS) {
		obj.RIR = s
	}
}
