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
func NewAutonomousSystem(number int64, opts ...STIXOption) (*AutonomousSystem, error) {
	if number == 0 {
		return nil, ErrInvalidParameter
	}
	base := newSTIXCyberObservableObject(TypeAutonomousSystem)
	obj := &AutonomousSystem{
		STIXCyberObservableObject: base,
		Number:                    number,
	}

	err := applyOptions(obj, opts)
	obj.ID = NewObservableIdentifier(fmt.Sprintf("[%d]", number), TypeAutonomousSystem)
	return obj, err
}
