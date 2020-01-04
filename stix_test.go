// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFromJSON(t *testing.T) {
	assert := assert.New(t)
	f, err := getResource("apt1-report.json")
	require.NoError(t, err)
	defer f.Close()

	data, err := ioutil.ReadAll(f)
	require.NoError(t, err)

	c, err := FromJSON(data)
	assert.NoError(err)
	assert.NotNil(c)

	assert.Len(c.AttackPatterns, 7)
	assert.Len(c.Identities, 5)
	assert.Len(c.Indicators, 12)
	assert.Len(c.IntrusionSets, 1)
	assert.Len(c.Malware, 6)
	assert.Len(c.MarkingDefinitions, 1)
	assert.Len(c.Relationships, 30)
	assert.Len(c.Reports, 1)
	assert.Len(c.ThreatActors, 5)
	assert.Len(c.Tools, 10)
}

func TestFromJSONAll(t *testing.T) {
	assert := assert.New(t)
	f, err := getResource("all.json")
	require.NoError(t, err)
	defer f.Close()

	data, err := ioutil.ReadAll(f)
	require.NoError(t, err)

	c, err := FromJSON(data)
	assert.NoError(err)
	assert.NotNil(c)

	assert.NotNil(c.ASs)
	assert.NotNil(c.Artifacts)
	assert.NotNil(c.AttackPatterns)
	assert.NotNil(c.Campaigns)
	assert.NotNil(c.CourseOfActions)
	assert.NotNil(c.Directories)
	assert.NotNil(c.DomainNames)
	assert.NotNil(c.EmailAddresses)
	assert.NotNil(c.EmailMessages)
	assert.NotNil(c.Files)
	assert.NotNil(c.Groups)
	assert.NotNil(c.IPv4Addresses)
	assert.NotNil(c.IPv6Addresses)
	assert.NotNil(c.Identities)
	assert.NotNil(c.Indicators)
	assert.NotNil(c.Infrastructures)
	assert.NotNil(c.IntrusionSets)
	assert.NotNil(c.LanguageContents)
	assert.NotNil(c.Locations)
	assert.NotNil(c.MACs)
	assert.NotNil(c.Malware)
	assert.NotNil(c.MalwareAnalysis)
	assert.NotNil(c.MarkingDefinitions)
	assert.NotNil(c.Mutexes)
	assert.NotNil(c.NetworkTraffic)
	assert.NotNil(c.Notes)
	assert.NotNil(c.ObservedData)
	assert.NotNil(c.Processes)
	assert.NotNil(c.RegistryKeys)
	assert.NotNil(c.Relationships)
	assert.NotNil(c.Reports)
	assert.NotNil(c.Sightings)
	assert.NotNil(c.Software)
	assert.NotNil(c.ThreatActors)
	assert.NotNil(c.Tools)
	assert.NotNil(c.URLs)
	assert.NotNil(c.UserAccounts)
	assert.NotNil(c.Vulnerabilities)
	assert.NotNil(c.X509Certificates)
}

func getResource(file string) (*os.File, error) {
	pth, err := filepath.Abs(filepath.Join("testresources", file))
	if err != nil {
		return nil, err
	}
	return os.OpenFile(pth, os.O_RDONLY, 0600)
}
