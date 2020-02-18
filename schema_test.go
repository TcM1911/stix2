// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

//+build long_test

package stix2_test

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TcM1911/stix2"
	"github.com/stretchr/testify/assert"
	"github.com/xeipuuv/gojsonschema"
)

func TestStixCollectionToBundle(t *testing.T) {
	sloader := gojsonschema.NewReferenceLoader("http://raw.githubusercontent.com/TcM1911/cti-stix2-json-schemas/stix2.1/schemas/common/bundle.json")

	t.Run("create_from_collection", func(t *testing.T) {
		assert := assert.New(t)
		c := &stix2.StixCollection{}
		ip, err := stix2.NewIPv4Address("10.0.0.1")
		assert.NoError(err)
		c.Add(ip)
		ip, err = stix2.NewIPv4Address("10.0.0.2")
		assert.NoError(err)
		c.Add(ip)

		b, err := c.ToBundle()
		assert.NoError(err)
		assert.NotNil(b)

		data, err := json.Marshal(b)
		assert.NoError(err)
		assert.NotNil(data)

		docloader := gojsonschema.NewBytesLoader(data)
		result, err := gojsonschema.Validate(sloader, docloader)
		assert.NoError(err)
		assert.True(result.Valid())
	})

	t.Run("examples", func(t *testing.T) {
		runFolder(t, sloader, "examples")
	})

	t.Run("threat-reports", func(t *testing.T) {
		runFolder(t, sloader, filepath.Join("examples", "threat-reports"))
	})
}

func runFolder(t *testing.T, sloader gojsonschema.JSONLoader, path string) {
	assert := assert.New(t)
	pth, err := filepath.Abs(filepath.Join("testresources", path))
	if err != nil {
		t.Fatalf("Error when resolving abs path to resource files: %s\n", err)
	}
	info, err := ioutil.ReadDir(pth)
	if err != nil {
		t.Fatalf("Error when loading resource files: %s\n", err)
	}
	for _, f := range info {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".json") {
			continue
		}
		fr, err := os.OpenFile(filepath.Join(pth, f.Name()), os.O_RDONLY, 0600)
		if err != nil {
			t.Fatalf("Error when opening the file: %s\n", err)
		}
		inData, err := ioutil.ReadAll(fr)
		assert.NoError(err)
		fr.Close()

		collection, err := stix2.FromJSON(inData)
		assert.NoError(err)
		assert.NotNil(collection)

		bundle, err := collection.ToBundle()
		assert.NoError(err)
		assert.NotNil(bundle)

		outData, err := json.Marshal(bundle)
		assert.NoError(err)
		assert.NotNil(outData)

		docloader := gojsonschema.NewBytesLoader(outData)
		result, err := gojsonschema.Validate(sloader, docloader)
		assert.NoError(err)
		assert.True(result.Valid(), f.Name()+" failed to validate")
		if !result.Valid() {
			for _, desc := range result.Errors() {
				fmt.Printf("- %s\n", desc)
			}
			// Dump the output data
			fmt.Println(string(outData))
		}
	}
}
