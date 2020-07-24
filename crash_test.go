package stix2_test

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/TcM1911/stix2"
	"github.com/stretchr/testify/assert"
)

func TestCrashCollectionAdd(t *testing.T) {
	runFolderTest(t, "crashesCollectionAdd", func(a *assert.Assertions, testData []byte) {
		a.NotPanics(func() {
			col, err := stix2.FromJSON(testData)
			a.Error(err)
			a.Nil(col)
		})
	})
}

type testFunc func(a *assert.Assertions, testData []byte)

func runFolderTest(t *testing.T, path string, fn testFunc) {
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
		if f.IsDir() {
			continue
		}
		fr, err := os.OpenFile(filepath.Join(pth, f.Name()), os.O_RDONLY, 0600)
		if err != nil {
			t.Fatalf("Error when opening the file: %s\n", err)
		}
		inData, err := ioutil.ReadAll(fr)
		assert.NoError(err)
		fr.Close()

		fn(assert, inData)
	}
}
