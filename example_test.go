// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2_test

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/TcM1911/stix2"
)

func ExampleFromJSON() {
	data := []byte(
		`
[
   {
	  "type":"infrastructure",
	  "spec_version":"2.1",
	  "id":"infrastructure--d09c50cf-5bab-465e-9e2d-543912148b73",
	  "created":"2016-11-22T09:22:30.000Z",
	  "modified":"2016-11-22T09:22:30.000Z",
	  "name":"Example Target List Host",
	  "infrastructure_types":[
		 "hosting-target-lists"
	  ]
   },
   {
	  "type":"relationship",
	  "spec_version":"2.1",
	  "id":"relationship--37ac0c8d-f86d-4e56-aee9-914343959a4c",
	  "created":"2016-11-23T08:17:27.000Z",
	  "modified":"2016-11-23T08:17:27.000Z",
	  "relationship_type":"uses",
	  "source_ref":"malware--3a41e552-999b-4ad3-bedc-332b6d9ff80c",
	  "target_ref":"infrastructure--d09c50cf-5bab-465e-9e2d-543912148b73"
   },
   {
	  "type":"malware",
	  "spec_version":"2.1",
	  "id":"malware--3a41e552-999b-4ad3-bedc-332b6d9ff80c",
	  "created":"2016-11-12T14:31:09.000Z",
	  "modified":"2016-11-12T14:31:09.000Z",
	  "is_family":true,
	  "malware_types":[
		 "bot"
	  ],
	  "name":"IMDDOS"
   },
   {
	  "type":"relationship",
	  "spec_version":"2.1",
	  "id":"relationship--81f12913-1372-4c96-85ec-E9034ac98aba",
	  "created":"2016-11-23T10:42:39.000Z",
	  "modified":"2016-11-23T10:42:39.000Z",
	  "relationship_type":"consists-of",
	  "source_ref":"infrastructure--d09c50cf-5bab-465e-9e2d-543912148b73",
	  "target_ref":"domain-name--3c10e93f-798e-5a26-a0c1-08156efab7f5"
   },
   {
	  "id":"domain-name--3c10e93f-798e-5a26-a0c1-08156efab7f5",
	  "type":"domain-name",
	  "value":"example.com"
   }
]
`)
	collection, _ := stix2.FromJSON(data)
	fmt.Println(collection.DomainName("domain-name--3c10e93f-798e-5a26-a0c1-08156efab7f5").Value)
	fmt.Println(collection.Malware("malware--3a41e552-999b-4ad3-bedc-332b6d9ff80c").Name)
	// Output:
	// example.com
	// IMDDOS
}

func ExampleStixCollection_ToBundle() {
	c := &stix2.StixCollection{}
	ip, err := stix2.NewIPv4Address("10.0.0.1")
	if err != nil {
		fmt.Println(err)
	}
	c.Add(ip)
	ip, err = stix2.NewIPv4Address("10.0.0.2")
	if err != nil {
		fmt.Println(err)
	}
	c.Add(ip)
	b, err := c.ToBundle()
	if err != nil {
		fmt.Println(err)
	}
	data, err := json.Marshal(b)
	if err != nil {
		fmt.Println(err)
	}
	if !bytes.Contains(data, []byte("10.0.0.2")) {
		fmt.Println("IP not in bundle")
	}
	// Output:
}
