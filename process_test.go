// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestProcess(t *testing.T) {
	assert := assert.New(t)

	ts := &Timestamp{time.Now()}
	testInt := int64(42)
	ref := Identifier("ref")
	env := map[string]string{"test": "map"}
	testStr := "test string"

	t.Run("missing_property", func(t *testing.T) {
		obj, err := NewProcess()
		assert.Nil(obj)
		assert.Equal(ErrPropertyMissing, err)
	})

	t.Run("payload_with_options", func(t *testing.T) {
		marking := &GranularMarking{}
		objmark := []Identifier{Identifier("id")}
		specVer := "2.0"

		opts := []ProcessOption{
			ProcessOptionGranularMarking(marking),
			ProcessOptionObjectMarking(objmark),
			ProcessOptionSpecVersion(specVer),
			ProcessOptionDefanged(true),
			ProcessOptionExtension("test", struct{}{}),
			//
			ProcessOptionIsHidden(true),
			ProcessOptionPID(testInt),
			ProcessOptionCreatedTime(ts),
			ProcessOptionCwd(testStr),
			ProcessOptionCommandLine(testStr),
			ProcessOptionEnvVars(env),
			ProcessOptionOpenedConnections([]Identifier{ref}),
			ProcessOptionCreatorUser(ref),
			ProcessOptionImage(ref),
			ProcessOptionParent(ref),
			ProcessOptionChild([]Identifier{ref}),
			nil, // test for nil to be passed in.
		}
		obj, err := NewProcess(opts...)
		assert.NotNil(obj)
		assert.NoError(err)
		assert.Equal(marking, obj.GranularMarking)
		assert.Equal(objmark, obj.ObjectMarking)
		assert.Equal(specVer, obj.SpecVersion)
		assert.True(obj.Defanged)

		assert.True(obj.IsHidden)
		assert.Equal(testInt, obj.PID)
		assert.Equal(ts, obj.CreatedTime)
		assert.Equal(testStr, obj.Cwd)
		assert.Equal(testStr, obj.CommandLine)
		assert.Equal(env, obj.EnvVars)
		assert.Equal([]Identifier{ref}, obj.OpenedConnections)
		assert.Equal(ref, obj.CreatorUser)
		assert.Equal(ref, obj.Image)
		assert.Equal(ref, obj.Parent)
		assert.Equal([]Identifier{ref}, obj.Child)
	})

	t.Run("process-extension", func(t *testing.T) {
		ext := &WindowsProcessExtension{
			ASLR:          true,
			InterityLevel: IntegrityLevelMedium,
		}
		f, _ := NewProcess(ProcessOptionExtension(ExtWindowsProcess, ext))
		assert.Len(f.Extensions, 1)
		stored := f.WindowsProcessExtension()
		assert.Equal(ext, stored)
	})

	t.Run("process-extension-nil", func(t *testing.T) {
		f, _ := NewProcess(ProcessOptionIsHidden(true))
		assert.Len(f.Extensions, 0)
		stored := f.WindowsProcessExtension()
		assert.Nil(stored)
	})

	t.Run("service-extension", func(t *testing.T) {
		ext := &WindowsServiceExtension{
			Name:          "name",
			StartType:     ServiceStartDisabled,
			ServiceType:   ServiceFileSystemDriver,
			ServiceStatus: ServiceStatusPausePending,
		}
		f, _ := NewProcess(ProcessOptionExtension(ExtWindowsService, ext))
		assert.Len(f.Extensions, 1)
		stored := f.WindowsServiceExtension()
		assert.Equal(ext, stored)
	})

	t.Run("service-extension-nil", func(t *testing.T) {
		f, _ := NewProcess(ProcessOptionIsHidden(true))
		assert.Len(f.Extensions, 0)
		stored := f.WindowsServiceExtension()
		assert.Nil(stored)
	})

	t.Run("parse_json", func(t *testing.T) {
		data := []byte(`{
  "type": "process",
  "spec_version": "2.1",
  "id": "process--f52a906a-0dfc-40bd-92f1-e7778ead38a9",
  "pid": 1221,
  "created": "2016-01-20T14:11:25.55Z",
  "command_line": "./gedit-bin --new-window",
  "image_ref": "file--e04f22d1-be2c-59de-add8-10f61d15fe20"
}`)
		var obj *Process
		err := json.Unmarshal(data, &obj)
		assert.NoError(err)
		assert.Equal(Identifier("process--f52a906a-0dfc-40bd-92f1-e7778ead38a9"), obj.ID)
		assert.Equal("2.1", obj.SpecVersion)
		assert.Equal(TypeProcess, obj.Type)
		assert.Equal("./gedit-bin --new-window", obj.CommandLine)
		assert.Equal(Identifier("file--e04f22d1-be2c-59de-add8-10f61d15fe20"), obj.Image)
		assert.Equal(int64(1221), obj.PID)
	})

	t.Run("parse_json-windows-process", func(t *testing.T) {
		data := []byte(`{
  "type": "process",
  "spec_version": "2.1",
  "id": "process--07bc30cad-ebc2-4579-881d-b9cdc7f2b33c",
  "pid": 314,
  "extensions": {
    "windows-process-ext": {
      "aslr_enabled": true,
      "dep_enabled": true,
      "priority": "HIGH_PRIORITY_CLASS",
      "owner_sid": "S-1-5-21-186985262-1144665072-74031268-1309"
    }
  }
}`)
		var obj *Process
		err := json.Unmarshal(data, &obj)
		assert.NoError(err)
		assert.Equal(Identifier("process--07bc30cad-ebc2-4579-881d-b9cdc7f2b33c"), obj.ID)
		assert.Equal("2.1", obj.SpecVersion)
		assert.Equal(TypeProcess, obj.Type)
		assert.Equal(int64(314), obj.PID)
		ext := obj.WindowsProcessExtension()
		assert.NotNil(ext)
		assert.True(ext.ASLR)
		assert.True(ext.DEP)
		assert.Equal("HIGH_PRIORITY_CLASS", ext.Priority)
		assert.Equal("S-1-5-21-186985262-1144665072-74031268-1309", ext.OwnerSID)
	})

	t.Run("parse_json-windows-service", func(t *testing.T) {
		data := []byte(`{
  "type": "process",
  "spec_version": "2.1",
  "id": "process--99ab297d-4c39-48ea-9d64-052d596864df",
  "pid": 2217,
  "command_line": "C:\\Windows\\System32\\sirvizio.exe /s",
  "image_ref": "file--3916128d-69af-5525-be7a-99fac2383a59",
  "extensions": {
    "windows-service-ext": {
      "service_name": "sirvizio",
      "display_name": "Sirvizio",
      "start_type": "SERVICE_AUTO_START",
      "service_type": "SERVICE_WIN32_OWN_PROCESS",
      "service_status": "SERVICE_RUNNING"
    }
  }
}`)
		var obj *Process
		err := json.Unmarshal(data, &obj)
		assert.NoError(err)
		assert.Equal(Identifier("process--99ab297d-4c39-48ea-9d64-052d596864df"), obj.ID)
		assert.Equal("2.1", obj.SpecVersion)
		assert.Equal(TypeProcess, obj.Type)
		assert.Equal(int64(2217), obj.PID)
		ext := obj.WindowsServiceExtension()
		assert.NotNil(ext)
		assert.Equal("sirvizio", ext.Name)
		assert.Equal("Sirvizio", ext.DisplayName)
		assert.Equal(ServiceStartAuto, ext.StartType)
		assert.Equal(ServiceWin32OwnProcess, ext.ServiceType)
		assert.Equal(ServiceStatusRunning, ext.ServiceStatus)
	})

	t.Run("integrity-type-unmarshal-short", func(t *testing.T) {
		d := []byte("A")
		var typ WindowsIntegrityLevel
		ptr := &typ
		err := ptr.UnmarshalJSON(d)
		assert.NoError(err)
		assert.Equal(IntegrityLevelUnknown, typ)
	})

	t.Run("integrity-type-unmarshal-invalid-key", func(t *testing.T) {
		d := []byte("AAAAA")
		var typ WindowsIntegrityLevel
		ptr := &typ
		err := ptr.UnmarshalJSON(d)
		assert.NoError(err)
		assert.Equal(IntegrityLevelUnknown, typ)
	})

	t.Run("service-start-type-unmarshal-short", func(t *testing.T) {
		d := []byte("A")
		var typ WindowsServiceStartType
		ptr := &typ
		err := ptr.UnmarshalJSON(d)
		assert.NoError(err)
		assert.Equal(ServiceStartUnknown, typ)
	})

	t.Run("service-start-type-unmarshal-invalid-key", func(t *testing.T) {
		d := []byte("AAAAA")
		var typ WindowsServiceStartType
		ptr := &typ
		err := ptr.UnmarshalJSON(d)
		assert.NoError(err)
		assert.Equal(ServiceStartUnknown, typ)
	})

	t.Run("service-type-unmarshal-short", func(t *testing.T) {
		d := []byte("A")
		var typ WindowsServiceType
		ptr := &typ
		err := ptr.UnmarshalJSON(d)
		assert.NoError(err)
		assert.Equal(ServiceUnknown, typ)
	})

	t.Run("service-start-type-unmarshal-invalid-key", func(t *testing.T) {
		d := []byte("AAAAA")
		var typ WindowsServiceType
		ptr := &typ
		err := ptr.UnmarshalJSON(d)
		assert.NoError(err)
		assert.Equal(ServiceUnknown, typ)
	})

	t.Run("service-status-type-unmarshal-short", func(t *testing.T) {
		d := []byte("A")
		var typ WindowsServiceStatusType
		ptr := &typ
		err := ptr.UnmarshalJSON(d)
		assert.NoError(err)
		assert.Equal(ServiceStatusUnknown, typ)
	})

	t.Run("service-status-type-unmarshal-invalid-key", func(t *testing.T) {
		d := []byte("AAAAA")
		var typ WindowsServiceStatusType
		ptr := &typ
		err := ptr.UnmarshalJSON(d)
		assert.NoError(err)
		assert.Equal(ServiceStatusUnknown, typ)
	})
}
