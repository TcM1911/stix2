// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestFile(t *testing.T) {
	assert := assert.New(t)

	val := "bad.exe"
	hash := Hashes{}
	hash[SHA1] = "0f01ed56a1e32a05e5ef96e4d779f34784af9a96"
	ref := Identifier("some ref")
	ts := &Timestamp{time.Now()}
	someString := "test string"
	hex := Hex("deadbeef")
	size := int64(42)

	t.Run("missing_property", func(t *testing.T) {
		obj, err := NewFile("", nil)
		assert.Nil(obj)
		assert.Equal(ErrInvalidParameter, err)
	})

	t.Run("with_property", func(t *testing.T) {
		obj, err := NewFile(val, nil, nil)
		assert.NotNil(obj)
		assert.NoError(err)
	})

	t.Run("payload_with_options", func(t *testing.T) {
		marking := make([]*GranularMarking, 0)
		objmark := []Identifier{Identifier("id")}
		specVer := "2.0"

		opts := []STIXOption{
			OptionGranularMarking(marking),
			OptionObjectMarking(objmark),
			OptionSpecVersion(specVer),
			OptionDefanged(true),
			//
			OptionSize(size),
			OptionNameEnc(someString),
			OptionMagicNumber(hex),
			OptionMimeType(someString),
			OptionCtime(ts),
			OptionMtime(ts),
			OptionAtime(ts),
			OptionParentDirectory(ref),
			OptionContains([]Identifier{ref}),
			OptionContent(ref),
		}
		obj, err := NewFile(val, hash, opts...)
		assert.NotNil(obj)
		assert.NoError(err)
		assert.Equal(marking, obj.GranularMarking)
		assert.Equal(objmark, obj.ObjectMarking)
		assert.Equal(specVer, obj.SpecVersion)
		assert.True(obj.Defanged)

		assert.Equal(val, obj.Name)
		assert.Equal(hash, obj.Hashes)
		assert.Equal(size, obj.Size)
		assert.Equal(someString, obj.NameEnc)
		assert.Equal(hex, obj.MagicNumber)
		assert.Equal(someString, obj.MimeType)
		assert.Equal(ts, obj.Ctime)
		assert.Equal(ts, obj.Mtime)
		assert.Equal(ts, obj.Atime)
		assert.Equal(ref, obj.ParentDirectory)
		assert.Equal([]Identifier{ref}, obj.Contains)
		assert.Equal(ref, obj.Content)
	})

	t.Run("id-generation", func(t *testing.T) {
		ext := &ArchiveFileExtension{Contains: []Identifier{Identifier("file--7c5c7956-5343-5a06-9710-db90e1331cac")}, Comment: someString}
		tests := []struct {
			hash Hashes
			name string
			exts *ArchiveFileExtension
			par  Identifier
			id   string
		}{
			{nil, val, nil, "", "file--77fc2ec7-ef85-57fa-9d5e-9e77693fc739"},
			{hash, val, nil, "", "file--7c5c7956-5343-5a06-9710-db90e1331cac"},
			{hash, val, ext, "", "file--893f22f2-e09e-50b6-b481-b94ac9b51a94"},
			{hash, val, ext, ref, "file--d233087f-68da-5e20-b3cb-42ad9edb401c"},
		}
		for _, test := range tests {
			opt := make([]STIXOption, 0, 2)
			if test.exts != nil {
				opt = append(opt, OptionExtension(ExtArchive, test.exts))
			}
			if test.par != "" {
				opt = append(opt, OptionParentDirectory(test.par))
			}
			obj, err := NewFile(test.name, test.hash, opt...)
			assert.NoError(err)
			assert.Equal(Identifier(test.id), obj.ID)
		}
	})

	t.Run("archive-extension", func(t *testing.T) {
		ext := &ArchiveFileExtension{Contains: []Identifier{ref}, Comment: someString}
		f, _ := NewFile(val, nil, OptionExtension(ExtArchive, ext))
		assert.Len(f.Extensions, 1)
		stored := f.ArchiveExtension()
		assert.Equal(ext, stored)
	})

	t.Run("ntfs-extension", func(t *testing.T) {
		ext := &NTFSFileExtension{SID: someString}
		f, _ := NewFile(val, nil, OptionExtension(ExtNTFS, ext))
		assert.Len(f.Extensions, 1)
		stored := f.NTFSExtension()
		assert.Equal(ext, stored)
	})

	t.Run("pdf-extension", func(t *testing.T) {
		ext := &PDFExtension{Version: someString}
		f, _ := NewFile(val, nil, OptionExtension(ExtPDF, ext))
		assert.Len(f.Extensions, 1)
		stored := f.PDFExtension()
		assert.Equal(ext, stored)
	})

	t.Run("raster-image-extension", func(t *testing.T) {
		ext := &RasterImageExtension{Height: int64(42)}
		f, _ := NewFile(val, nil, OptionExtension(ExtRasterImage, ext))
		assert.Len(f.Extensions, 1)
		stored := f.RasterImageExtension()
		assert.Equal(ext, stored)
	})

	t.Run("pe-extension", func(t *testing.T) {
		ext := &WindowsPEBinaryExtension{PEType: WindowsPEDLL, ImpHash: someString}
		f, _ := NewFile(val, nil, OptionExtension(ExtWindowsPEBinary, ext))
		assert.Len(f.Extensions, 1)
		stored := f.WindowsPEBinaryExtension()
		assert.Equal(ext, stored)
	})

	t.Run("parse_json", func(t *testing.T) {
		data := []byte(`{
  "type": "file",
  "spec_version": "2.1",
  "id": "file--66156fad-2a0d-5237-bba4-ba1912887cfe",
  "hashes": {
    "SHA-256": "ceafbfd424be2ca4a5f0402cae090dda2fb0526cf521b60b60077c0f622b285a"
  },
  "parent_directory_ref": "directory--93c0a9b0-520d-545d-9094-1a08ddf46b05",
  "name": "qwerty.dll"
}`)
		var obj *File
		err := json.Unmarshal(data, &obj)
		assert.NoError(err)
		assert.Equal(Identifier("file--66156fad-2a0d-5237-bba4-ba1912887cfe"), obj.ID)
		assert.Equal("2.1", obj.SpecVersion)
		assert.Equal(TypeFile, obj.Type)
		assert.Equal("qwerty.dll", obj.Name)
		assert.Equal("ceafbfd424be2ca4a5f0402cae090dda2fb0526cf521b60b60077c0f622b285a", obj.Hashes[SHA256])
	})

	t.Run("parse_json_pe", func(t *testing.T) {
		data := []byte(`{
  "type": "file",
  "spec_version": "2.1",
  "id": "file--fb0419a8-f09c-57f8-be64-71a80417591c",
  "extensions": {
    "windows-pebinary-ext": {
      "pe_type": "exe",
      "machine_hex": "014c",
      "number_of_sections": 4,
      "time_date_stamp": "2016-01-22T12:31:12Z",
      "pointer_to_symbol_table_hex": "74726144",
      "number_of_symbols": 4542568,
      "size_of_optional_header": 224,
      "characteristics_hex": "818f",
      "optional_header": {
        "magic_hex": "010b",
        "major_linker_version": 2,
        "minor_linker_version": 25,
        "size_of_code": 512,
        "size_of_initialized_data": 283648,
        "size_of_uninitialized_data": 0,
        "address_of_entry_point": 4096,
        "base_of_code": 4096,
        "base_of_data": 8192,
        "image_base": 14548992,
        "section_alignment": 4096,
        "file_alignment": 4096,
        "major_os_version": 1,
        "minor_os_version": 0,
        "major_image_version": 0,
        "minor_image_version": 0,
        "major_subsystem_version": 4,
        "minor_subsystem_version": 0,
        "win32_version_value_hex": "00",
        "size_of_image": 299008,
        "size_of_headers": 4096,
        "checksum_hex": "00",
        "subsystem_hex": "03",
        "dll_characteristics_hex": "00",
        "size_of_stack_reserve": 100000,
        "size_of_stack_commit": 8192,
        "size_of_heap_reserve": 100000,
        "size_of_heap_commit": 4096,
        "loader_flags_hex": "abdbffde",
        "number_of_rva_and_sizes": 3758087646
      },
      "sections": [
        {
          "name": "CODE",
          "entropy": 0.061089
        },
        {
          "name": "DATA",
          "entropy": 7.980693
        },
        {
          "name": "NicolasB",
          "entropy": 0.607433
        },
        {
          "name": ".idata",
          "entropy": 0.607433
        }
      ]
    }
  }
}`)
		var obj *File
		err := json.Unmarshal(data, &obj)
		assert.NoError(err)
		assert.Equal(Identifier("file--fb0419a8-f09c-57f8-be64-71a80417591c"), obj.ID)
		assert.Equal("2.1", obj.SpecVersion)
		assert.Equal(TypeFile, obj.Type)
		pext := obj.WindowsPEBinaryExtension()
		assert.Equal(WindowsPEExe, pext.PEType)
		assert.Equal(Hex("818f"), pext.Characteristics)
		assert.Equal("CODE", pext.Sections[0].Name)
	})
}
