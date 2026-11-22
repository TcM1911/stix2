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
	runFolderTest(t, "crashesCollectionAdd", func(a *assert.Assertions, name string, testData []byte) {
		a.NotPanics(func() {
			col, err := stix2.FromJSON(testData, stix2.DropCustomOption())
			switch name {
			case "0f40f3730365a0a37570562c8319b8fc38b2193e":
				a.NoError(err)
				if a.NotNil(col) {
					a.Len(col.GetAll(stix2.TypeCampaign), 1)
					a.Len(col.GetAll(stix2.TypeRelationship), 1)
				}
			case "280c70497ac5ea11fdeb12989706a4cf31f265a3":
				a.NoError(err)
				if a.NotNil(col) {
					a.Len(col.GetAll(stix2.TypeMarkingDefinition), 1)
				}
			case "3daecaffffa67fd33432d27187384eafb72fadf7", "e1c892f503235cdbc85963459136e400a28f5cc8":
				a.NoError(err)
				if a.NotNil(col) {
					a.Len(col.GetAll(stix2.TypeIdentity), 1)
					a.Len(col.GetAll(stix2.TypeIndicator), 2)
					a.Len(col.GetAll(stix2.TypeRelationship), 3)
					a.Len(col.GetAll(stix2.TypeCourseOfAction), 1)
				}
			case "2d8c993e1244423bd6496a8825e939b9cef9ad38":
				a.NoError(err)
				if a.NotNil(col) {
					a.Len(col.GetAll(stix2.TypeLanguageContent), 1)
				}
			case "318776de43caac14fee78e0c81459404efb557ca":
				a.NoError(err, name)
				if a.NotNil(col) {
					a.Len(col.GetAll(stix2.TypeIdentity), 4)
					a.Len(col.GetAll(stix2.TypeIndicator), 11)
					a.Len(col.GetAll(stix2.TypeAttackPattern), 7)
					a.Len(col.GetAll(stix2.TypeRelationship), 30)
				}
			case "8a771bf5a0696eb5a0d800ebdb6fa38e32e5add9":
				a.NoError(err, name)
				if a.NotNil(col) {
					a.Len(col.GetAll(stix2.TypeIdentity), 4)
					a.Len(col.GetAll(stix2.TypeIndicator), 12)
					a.Len(col.GetAll(stix2.TypeAttackPattern), 7)
					a.Len(col.GetAll(stix2.TypeRelationship), 30)
				}
			case "e74eb7ab46535f74e89cfb9bf511f7cc24dced39":
				a.Error(err)
				a.Nil(col)
			case "564cbed382a71becf1263f3be737de1cce1e00fa":
				a.NoError(err)
				if a.NotNil(col) {
					a.Len(col.GetAll(stix2.TypeIndicator), 1)
				}
			case "cd49bb32df487f99859d5093029804d8819c18ab":
				a.NoError(err)
				if a.NotNil(col) {
					a.Len(col.GetAll(stix2.TypeThreatActor), 3)
				}
			default:
				a.Error(err, name)
				a.Nil(col, name)
			}
		})
	})
}

type testFunc func(a *assert.Assertions, name string, testData []byte)

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

		fn(assert, f.Name(), inData)
	}
}
