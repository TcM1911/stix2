// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import (
	"encoding/json"
	"fmt"
)

// Bundle is a collection of arbitrary STIX Objects grouped together in a
// single container. A Bundle does not have any semantic meaning and the
// objects contained within the Bundle are not considered related by virtue of
// being in the same Bundle.
type Bundle struct {
	// Type property identifies the type of object.
	Type StixType `json:"type"`
	// ID is an identifier for this Bundle. The id property for the Bundle is
	// designed to help tools that may need it for processing, but tools are
	// not required to store or track it. Tools that consume STIX should not
	// rely on the ability to refer to bundles by ID.
	ID Identifier `json:"id"`
	// Objects specifies a set of one or more STIX Objects.
	Objects []json.RawMessage `json:"objects,omitempty"`
}

// NewBundle creates a new STIX Bundle.
func NewBundle(objs ...StixObject) (*Bundle, error) {
	b := &Bundle{Type: TypeBundle, ID: NewIdentifier(TypeBundle)}
	a := make([]json.RawMessage, 0, len(objs))
	for _, v := range objs {
		data, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("error when encoding %s to JSON: %w", v.GetID(), err)
		}
		a = append(a, data)
	}
	b.Objects = a
	return b, nil
}
