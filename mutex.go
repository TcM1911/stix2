// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import "fmt"

// Mutex represents the properties of a mutual exclusion (mutex) object.
type Mutex struct {
	STIXCyberObservableObject
	// Name specifies the name of the mutex object.
	Name string `json:"name"`
}

// NewMutex creates a new Mutex object.
func NewMutex(value string, opts ...STIXOption) (*Mutex, error) {
	if value == "" {
		return nil, ErrInvalidParameter
	}
	base := newSTIXCyberObservableObject(TypeMutex)
	obj := &Mutex{
		STIXCyberObservableObject: base,
		Name:                      value,
	}

	err := applyOptions(obj, opts)
	obj.ID = NewObservableIdentifier(fmt.Sprintf("[\"%s\"]", value), TypeMutex)
	return obj, err
}
