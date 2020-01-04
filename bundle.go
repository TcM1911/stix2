// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import "encoding/json"

// Bundle is a collection of arbitrary STIX Objects grouped together in a
// single container. A Bundle does not have any semantic meaning and the
// objects contained within the Bundle are not considered related by virtue of
// being in the same Bundle.
type Bundle struct {
	// Objects specifies a set of one or more STIX Objects.
	Objects []json.RawMessage `json:"objects,omitempty"`
}
