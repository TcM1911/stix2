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
func NewMutex(value string, opts ...MutexOption) (*Mutex, error) {
	if value == "" {
		return nil, ErrInvalidParameter
	}
	base := newSTIXCyberObservableObject(TypeMutex)
	obj := &Mutex{
		STIXCyberObservableObject: base,
		Name:                      value,
	}

	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(obj)
	}
	obj.ID = NewObservableIdenfier(fmt.Sprintf("[\"%s\"]", value), TypeMutex)
	return obj, nil
}

// MutexOption is an optional parameter when constructing a Mutex object.
type MutexOption func(a *Mutex)

/*
	Base object options
*/

// MutexOptionSpecVersion sets the STIX spec version.
func MutexOptionSpecVersion(ver string) MutexOption {
	return func(obj *Mutex) {
		obj.SpecVersion = ver
	}
}

// MutexOptionObjectMarking sets the object marking attribute.
func MutexOptionObjectMarking(om []Identifier) MutexOption {
	return func(obj *Mutex) {
		obj.ObjectMarking = om
	}
}

// MutexOptionGranularMarking sets the granular marking attribute.
func MutexOptionGranularMarking(gm []*GranularMarking) MutexOption {
	return func(obj *Mutex) {
		obj.GranularMarking = gm
	}
}

// MutexOptionDefanged sets the defanged attribute.
func MutexOptionDefanged(b bool) MutexOption {
	return func(obj *Mutex) {
		obj.Defanged = b
	}
}

// MutexOptionExtension adds an extension.
func MutexOptionExtension(name string, value interface{}) MutexOption {
	return func(obj *Mutex) {
		// Ignoring the error.
		obj.addExtension(name, value)
	}
}
