// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

/*
Package stix2 is a pure Go library for working with Structured Threat
Information Expression (STIX™) version 2.x data.

Parsing STIX JSON data:

	collection, err := stix2.FromJSON(jsonData)

Creating a STIX Bundle, is as easy as creating a set of STIX objects and add
them to the StixCollection. The Bundle can be created by calling the `ToBundle`
method on the StixCollection object. The Bundle can be serialized to `JSON`
using the `JSON` encoder in the standard library.

	c := &stix2.StixCollection{}
	ip, err := stix2.NewIPv4Address("10.0.0.1")
	c.Add(ip)
	ip, err = stix2.NewIPv4Address("10.0.0.2")
	c.Add(ip)
	b, err := c.ToBundle()
	data, err := json.Marshal(b)

*/
package stix2
