// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import "errors"

var (
	// ErrPropertyMissing is returned if not at least one of the required
	// properties are missing
	ErrPropertyMissing = errors.New("at least one of the description, url, or externalID properties MUST be present")
	// ErrInvalidProperty is returned if the value for a property is invalid.
	ErrInvalidProperty = errors.New("invalid value for the property")
	// ErrInvalidParameter is returned if function is called with an invalid
	// function parameter.
	ErrInvalidParameter = errors.New("invalid parameter")
)
