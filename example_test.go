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

func ExampleCollection_ToBundle() {
	c := stix2.New()
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

func Example() {
	// Taken from: https://docs.oasis-open.org/cti/stix/v2.1/csprd02/stix-v2.1-csprd02.html#_Toc26789941
	collection := stix2.New()
	domain, err := stix2.NewDomainName("example.com")
	if err != nil {
		fmt.Println(err)
	}
	collection.Add(domain)

	mal, err := stix2.NewMalware(
		false,
		stix2.OptionName("IMDDOS"),
		stix2.OptionTypes([]string{stix2.MalwareTypeBot}),
	)
	if err != nil {
		fmt.Println(err)
	}
	collection.Add(mal)

	infra, err := stix2.NewInfrastructure(
		"Example Target List Host",
	)
	if err != nil {
		fmt.Println(err)
	}
	collection.Add(infra)

	ref, err := mal.AddUses(infra.ID)
	if err != nil {
		fmt.Println(err)
	}
	collection.Add(ref)

	ref, err = infra.AddConsistsOf(domain.ID)
	if err != nil {
		fmt.Println(err)
	}
	collection.Add(ref)

	b, err := collection.ToBundle()
	if err != nil {
		fmt.Println(err)
		return
	}
	data, err := json.MarshalIndent(b, "", "\t")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(data))
}

func ExampleCustomObject() {
	// Define the custom fields
	ext := &stix2.CustomObject{}
	ext.Set("some_new_property", "a string value")

	// The extension definition.
	ed, _ := stix2.NewExtensionDefinition(
		"A custom extension",
		"https://example.com/v1/schema",
		"1.0",
		[]stix2.ExtensionType{stix2.ExtensionTypePropertyExtension},
	)

	// Create a DomainName object with the additional field.
	d, _ := stix2.NewDomainName("example.com", stix2.OptionExtension(string(ed.ID), ext))

	fmt.Println(d.Extensions[string(ed.ID)].(*stix2.CustomObject).GetAsString("some_new_property"))

	//Output:
	// a string value
}

func ExampleCustomObject_attack() {
	data := []byte(`[{
		"id": "attack-pattern--3fc9b85a-2862-4363-a64d-d692e3ffbee0",
		"description": "Adversaries may search for common password storage locations to obtain user credentials. Passwords are stored in several places on a system, depending on the operating system or application holding the credentials. There are also specific applications that store passwords to make it easier for users manage and maintain. Once credentials are obtained, they can be used to perform lateral movement and access restricted information.",
		"name": "Credentials from Password Stores",
		"created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
		"object_marking_refs": [
			"marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
		],
		"external_references": [
			{
				"source_name": "mitre-attack",
				"external_id": "T1555",
				"url": "https://attack.mitre.org/techniques/T1555"
			}
		],
		"type": "attack-pattern",
		"kill_chain_phases": [
			{
				"kill_chain_name": "mitre-attack",
				"phase_name": "credential-access"
			}
		],
		"modified": "2021-04-29T21:00:19.428Z",
		"created": "2020-02-11T18:48:28.456Z",
		"x_mitre_platforms": [
			"Linux",
			"macOS",
			"Windows"
		],
		"x_mitre_is_subtechnique": false,
		"x_mitre_version": "1.0",
		"x_mitre_detection": "Monitor system calls, file read events, and processes for suspicious activity that could indicate searching for a password  or other activity related to performing keyword searches (e.g. password, pwd, login, store, secure, credentials, etc.) in process memory for credentials. File read events should be monitored surrounding known password storage applications.",
		"x_mitre_permissions_required": [
			"Administrator"
		],
		"x_mitre_data_sources": [
			"Process: Process Creation",
			"File: File Access",
			"Command: Command Execution",
			"Process: OS API Execution",
			"Process: Process Access"
		],
		"spec_version": "2.1",
		"x_mitre_domains": [
			"enterprise-attack"
		],
		"x_mitre_modified_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5"
}]`)

	col, err := stix2.FromJSON(data)
	if err != nil {
		fmt.Println(err)
	}

	obj := col.AttackPattern(stix2.Identifier("attack-pattern--3fc9b85a-2862-4363-a64d-d692e3ffbee0"))
	fmt.Println(obj.Name)

	// Get the custom properties.
	ext := obj.GetExtendedTopLevelProperties()
	fmt.Println(ext.GetAsString("x_mitre_version"))

	//Output:
	// Credentials from Password Stores
	// 1.0
}
