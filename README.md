[![Build Status](https://travis-ci.com/TcM1911/stix2.svg?branch=master)](https://travis-ci.com/TcM1911/stix2)
[![Go Report Card](https://goreportcard.com/badge/github.com/TcM1911/stix2)](https://goreportcard.com/report/github.com/TcM1911/stix2)
![GitHub tag (latest SemVer)](https://img.shields.io/github/v/tag/TcM1911/stix2?label=Latest)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/TcM1911/stix2)
[![Go Doc](https://img.shields.io/badge/godoc-reference-blue.svg?style=flat-square)](http://godoc.org/github.com/TcM1911/stix2)
[![codecov](https://codecov.io/gh/TcM1911/stix2/branch/master/graph/badge.svg)](https://codecov.io/gh/TcM1911/stix2)

# stix2
A pure Go library for working with Structured Threat Information Expression
(STIX™) version 2.x data.

## Parsing STIX JSON data

The library provides a helper function to parse STIX JSON. It can handle
both the bundle object and JSON objects as a JSON array. The function returns
a `StixCollection` object that holds all the extracted STIX objects.

```go
collection, err := stix2.FromJSON(jsonData)
```

## Creating a STIX Bundle

Creating a STIX Bundle, is as easy as creating a set of STIX objects and add
them to the StixCollection. The Bundle can be created by calling the `ToBundle`
method on the StixCollection object. The Bundle can be serialized to `JSON`
using the `JSON` encoder in the standard library.

```go
c := &stix2.StixCollection{}
ip, err := stix2.NewIPv4Address("10.0.0.1")
c.Add(ip)
ip, err = stix2.NewIPv4Address("10.0.0.2")
c.Add(ip)
b, err := c.ToBundle()
data, err := json.Marshal(b)
```


## Example of a malware using an infrastructure
Taken from: https://docs.oasis-open.org/cti/stix/v2.1/csprd02/stix-v2.1-csprd02.html#_Toc26789941

```go
collection := &stix2.StixCollection{}
domain, err := stix2.NewDomain("example.com")
collection.Add(domain)

mal, err := stix2.NewMalware(
	[]string{stix2.MalwareTypeBot},
	false,
	stix2.MalwareOptionName("IMDDOS"),
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
```

## To-do

- [x] Provide a solution to create a bundle from the collection object.
- [ ] Add more data validations when creating objects
- [ ] Support and documentation for customization
- [ ] Ensure SITX 2.0 is supported

