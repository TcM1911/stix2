package stix2

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCyberObservableOptions(t *testing.T) {
	a := assert.New(t)

	type testObject struct {
		STIXCyberObservableObject
	}

	t.Run("happy_path", func(t *testing.T) {
		o := &testObject{}

		err := OptionSpecVersion("2.1")(o)
		a.NoError(err)
		a.Equal("2.1", o.SpecVersion)

		err = OptionDefanged(true)(o)
		a.NoError(err)
		a.True(o.Defanged)

		ids := []Identifier{Identifier("test-id")}
		err = OptionObjectMarking(ids)(o)
		a.NoError(err)
		a.Equal(ids, o.ObjectMarking)

		gms := []*GranularMarking{{Lang: "test"}}
		err = OptionGranularMarking(gms)(o)
		a.NoError(err)
		a.Equal(gms, o.GranularMarking)

		ext := map[string]string{}
		ext["TestField"] = "test value"

		err = OptionExtension("TestExtension", ext)(o)
		a.NoError(err)
		a.Len(o.Extensions, 1)
		a.Contains(o.Extensions["TestExtension"].(map[string]string)["TestField"], "test value")
	})

	t.Run("nil_object", func(t *testing.T) {
		err := OptionDefanged(true)(nil)
		a.Error(err)
		a.Equal("object must be a pointer type", err.Error())
	})

	t.Run("empty_object", func(t *testing.T) {
		obj := &emptryTestStruct{}
		err := OptionDefanged(true)(obj)
		a.Error(err)
		a.Equal("failed to apply Defanged option: Defanged not found", err.Error())
	})

	t.Run("not_pinter_to_struct", func(t *testing.T) {
		obj := badType("Test")
		err := OptionDefanged(true)(&obj)
		a.Error(err)
		a.Equal("object has to be a pointer to struct", err.Error())
	})

	t.Run("field_in_main_object", func(t *testing.T) {
		obj := &testStructWithDefanged{}
		err := OptionDefanged(true)(obj)
		a.NoError(err)
		a.True(obj.Defanged)
	})

	t.Run("wrong_field_kind_1", func(t *testing.T) {
		obj := &structWithWrongKind{}
		err := OptionDefanged(true)(obj)
		a.Error(err)
		a.Equal("failed to apply Defanged option: STIXCyberObservableObject is not of struct type", err.Error())
	})

	t.Run("wrong_field_kind_2", func(t *testing.T) {
		obj := &structWithWrongFieldKind{}
		err := OptionDefanged(true)(obj)
		a.Error(err)
		a.Equal("bool field is not a Defanged type", err.Error())
	})

	t.Run("extensions_wrong_field_kind_1", func(t *testing.T) {
		obj := &structWithWrongKind{}
		err := OptionExtension("tesst", "")(obj)
		a.Error(err)
		a.Equal("object can not have extensions", err.Error())
	})

	t.Run("extensions_wrong_extension_kind", func(t *testing.T) {
		obj := &struct {
			emptryTestStruct
			STIXCyberObservableObject struct {
				Extensions string
			}
		}{}
		err := OptionExtension("test", "")(obj)
		a.Error(err)
		a.Equal("object can not have extensions", err.Error())
	})

	t.Run("extensions_no_field", func(t *testing.T) {
		obj := &struct {
			emptryTestStruct
			STIXCyberObservableObject struct {
				Something string
			}
		}{}
		err := OptionExtension("test", "")(obj)
		a.Error(err)
		a.Equal("object can not have extensions", err.Error())
	})

	t.Run("extenstion_not_pinter_to_struct", func(t *testing.T) {
		// obj := badType("Test")
		err := OptionExtension("test", "")(nil)
		a.Error(err)
		a.Equal("object must be a pointer type", err.Error())
	})

	t.Run("applyOptions_error", func(t *testing.T) {
		err := applyOptions(nil, []STIXOption{OptionDefanged(true)})
		a.Error(err)
		a.Equal("object must be a pointer type", err.Error())
	})
}

type emptryTestStruct struct{}

func (s *emptryTestStruct) GetCreated() *time.Time {
	panic("Failed")
}

func (s *emptryTestStruct) GetModified() *time.Time {
	panic("Failed")
}

func (s *emptryTestStruct) GetType() STIXType {
	panic("Failed")
}

func (s *emptryTestStruct) GetID() Identifier {
	panic("Failed")
}

type testStructWithDefanged struct {
	emptryTestStruct
	Defanged bool
}

type structWithWrongKind struct {
	emptryTestStruct
	STIXCyberObservableObject bool
}

type structWithWrongFieldKind struct {
	emptryTestStruct
	Defanged string
}

type badType string

func (s *badType) GetCreated() *time.Time {
	panic("Failed")
}

func (s *badType) GetModified() *time.Time {
	panic("Failed")
}

func (s *badType) GetType() STIXType {
	panic("Failed")
}

func (s *badType) GetID() Identifier {
	panic("Failed")
}

func TestDomainObjectOptions(t *testing.T) {
	a := assert.New(t)

	type testObject struct {
		STIXDomainObject
	}

	o := &testObject{}

	ts := &Timestamp{time.Now()}
	id := Identifier("test-id")
	sarray := []string{"test slice"}
	refs := []*ExternalReference{{Name: "Test ref"}}
	gms := []*GranularMarking{{Lang: "Test marking"}}

	err := OptionSpecVersion("2.1")(o)
	a.NoError(err)
	a.Equal("2.1", o.SpecVersion)

	err = OptionCreatedBy(id)(o)
	a.NoError(err)
	a.Equal(id, o.CreatedBy)

	err = OptionCreated(ts)(o)
	a.NoError(err)
	a.Equal(ts, o.Created)

	err = OptionModified(ts)(o)
	a.NoError(err)
	a.Equal(ts, o.Modified)

	err = OptionRevoked(true)(o)
	a.NoError(err)
	a.True(o.Revoked)

	err = OptionLabels(sarray)(o)
	a.NoError(err)
	a.Equal(sarray, o.Labels)

	err = OptionConfidence(100)(o)
	a.NoError(err)
	a.Equal(100, o.Confidence)

	err = OptionLang("en")(o)
	a.NoError(err)
	a.Equal("en", o.Lang)

	err = OptionExternalReferences(refs)(o)
	a.NoError(err)
	a.Equal(refs, o.ExternalReferences)

	err = OptionObjectMarking([]Identifier{id})(o)
	a.NoError(err)
	a.Contains(o.ObjectMarking, id)

	err = OptionGranularMarking(gms)(o)
	a.NoError(err)
	a.Equal(gms, o.GranularMarking)
}
