// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import "fmt"

// AutonomousSystem object represents the properties of an Autonomous System (AS).
type AutonomousSystem struct {
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

// NewAutonomousSystem creates a new AutonomousSystem object.
func NewAutonomousSystem(number int64, opts ...AutonomousSystemOption) (*AutonomousSystem, error) {
	if number == 0 {
		return nil, ErrInvalidParameter
	}
	base := newSTIXCyberObservableObject(TypeAutonomousSystem)
	obj := &AutonomousSystem{
		STIXCyberObservableObject: base,
		Number:                    number,
	}

	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(obj)
	}
	obj.ID = NewObservableIdenfier(fmt.Sprintf("[%d]", number), TypeAutonomousSystem)
	return obj, nil
}

// AutonomousSystemOption is an optional parameter when constructing a
// AS object.
type AutonomousSystemOption func(a *AutonomousSystem)

/*
	Base object options
*/

// ASOptionSpecVersion sets the STIX spec version.
func ASOptionSpecVersion(ver string) AutonomousSystemOption {
	return func(obj *AutonomousSystem) {
		obj.SpecVersion = ver
	}
}

// ASOptionObjectMarking sets the object marking attribute.
func ASOptionObjectMarking(om []Identifier) AutonomousSystemOption {
	return func(obj *AutonomousSystem) {
		obj.ObjectMarking = om
	}
}

// ASOptionGranularMarking sets the granular marking attribute.
func ASOptionGranularMarking(gm []*GranularMarking) AutonomousSystemOption {
	return func(obj *AutonomousSystem) {
		obj.GranularMarking = gm
	}
}

// ASOptionDefanged sets the defanged attribute.
func ASOptionDefanged(b bool) AutonomousSystemOption {
	return func(obj *AutonomousSystem) {
		obj.Defanged = b
	}
}

// ASOptionExtension adds an extension.
func ASOptionExtension(name string, value interface{}) AutonomousSystemOption {
	return func(obj *AutonomousSystem) {
		// Ignoring the error.
		obj.addExtension(name, value)
	}
}

/*
	AS object options
*/

// ASOptionName sets the name type attribute.
func ASOptionName(s string) AutonomousSystemOption {
	return func(obj *AutonomousSystem) {
		obj.Name = s
	}
}

// ASOptionRIR sets the rir attribute.
func ASOptionRIR(s string) AutonomousSystemOption {
	return func(obj *AutonomousSystem) {
		obj.RIR = s
	}
}
