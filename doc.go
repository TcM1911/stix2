// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

/*
Package stix2 is a pure Go library for working with Structured Threat
Information Expression (STIX™) version 2.x data.

Parsing STIX JSON data:

	collection, err := stix2.FromJSON(jsonData)

Creating a STIX Bundle, is as easy as creating a set of STIX objects and add
them to the Collection. The Bundle can be created by calling the `ToBundle`
method on the Collection object. The Bundle can be serialized to `JSON`
using the `JSON` encoder in the standard library.

	c := stix2.New()
	ip, err := stix2.NewIPv4Address("10.0.0.1")
	c.Add(ip)
	ip, err = stix2.NewIPv4Address("10.0.0.2")
	c.Add(ip)
	b, err := c.ToBundle()
	data, err := json.Marshal(b)

Example of a malware using an infrastructure. Taken from:
https://docs.oasis-open.org/cti/stix/v2.1/csprd02/stix-v2.1-csprd02.html#_Toc26789941

	collection := stix2.New()
	domain, err := stix2.NewDomainName("example.com")
	collection.Add(domain)

	mal, err := stix2.NewMalware(
		false,
		stix2.OptionName("IMDDOS"),
		stix2.OptionTypes([]string{stix2.MalwareTypeBot}),
	)
	collection.Add(mal)

	infra, err := stix2.NewInfrastructure(
		"Example Target List Host",
		[]string{stix2.InfrastructureTypeHostingTargetLists},
	)
	collection.Add(infra)

	ref, err := mal.AddUses(infra.ID)
	collection.Add(ref)

	ref, err = infra.AddConsistsOf(domain.ID)
	collection.Add(ref)

	b, err := collection.ToBundle()
	data, err := json.MarshalIndent(b, "", "\t")

Extensions and Customization

With the release of version 2.1 of the specification custom properties
has been deprecated. Instead, `property-extension` functionality should
be used. This library supports parsing objects with old custom properties
for backwards compatibility. The fields can be accessed via the
`GetExtendedTopLevelProperties` method.

See the examples on how to work with extensions.
*/
package stix2
