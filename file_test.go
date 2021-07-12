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

	t.Run("parse-archive", func(t *testing.T) {
		data := []byte(`{
			"type": "file",
			"spec_version": "2.1",
			"id": "file--9a1f834d-2506-5367-baec-7aa63996ac43",
			"name": "foo.zip",
			"hashes": {
			  "SHA-256": "35a01331e9ad96f751278b891b6ea09699806faedfa237d40513d92ad1b7100f"
			},
			"mime_type": "application/zip",
			"extensions": {
			  "archive-ext": {
				"contains_refs": [
				  "file--019fde1c-94ca-5967-8b3c-a906a51d87ac",
				  "file--94fc2163-dec3-5715-b824-6e689c4de865",
				  "file--d07ff290-d7e0-545b-a2ff-04602a9e0b73"
				]
			  }
			}
		  }
`)

		var obj *File
		err := json.Unmarshal(data, &obj)
		assert.NoError(err)

		ext := obj.ArchiveExtension()
		assert.NotNil(ext)
		assert.Contains(ext.Contains, Identifier("file--94fc2163-dec3-5715-b824-6e689c4de865"))
	})

	t.Run("ntfs", func(t *testing.T) {
		data := []byte(`{
			"type": "file",
			"spec_version": "2.1",
			"id": "file--73c4cd13-7206-5100-88ef-822c42d3f02c",
			"hashes": {
			  "SHA-256": "35a01331e9ad96f751278b891b6ea09699806faedfa237d40513d92ad1b7100f"
			},
			"extensions": {
			  "ntfs-ext": {
				"alternate_data_streams": [
				  {
					"name": "second.stream",
					"size": 25536
				  }
				]
			  }
			}
		  }
`)
		var obj *File
		err := json.Unmarshal(data, &obj)
		assert.NoError(err)

		ext := obj.NTFSExtension()
		assert.NotNil(ext)
		assert.Equal("second.stream", ext.AltDataStreams[0].Name)
		assert.Equal(int64(25536), ext.AltDataStreams[0].Size)
	})

	t.Run("pdf", func(t *testing.T) {
		data := []byte(`{
			"type": "file",
			"spec_version": "2.1",
			"id": "file--ec3415cc-5f4f-5ec8-bdb1-6f86996ae66d",
			"name": "example.pdf",
			"extensions": {
			  "pdf-ext": {
				"version": "1.7",
				"document_info_dict": {
				  "Title": "Sample document",
				  "Author": "Adobe Systems Incorporated",
				  "Creator": "Adobe FrameMaker 5.5.3 for Power Macintosh",
				  "Producer": "Acrobat Distiller 3.01 for Power Macintosh",
				  "CreationDate": "20070412090123-02"
				},
				"pdfid0": "DFCE52BD827ECF765649852119D",
				"pdfid1": "57A1E0F9ED2AE523E313C"
			  }
			}
		  }
`)

		var obj *File
		err := json.Unmarshal(data, &obj)
		assert.NoError(err)

		ext := obj.PDFExtension()
		assert.NotNil(ext)
		assert.Equal("1.7", ext.Version)
		assert.Equal("Adobe Systems Incorporated", ext.DocumentInfo["Author"])
		assert.Equal("DFCE52BD827ECF765649852119D", ext.PDFid0)
	})

	t.Run("raster-image", func(t *testing.T) {
		data := []byte(`{
			"type": "file",
			"spec_version": "2.1",
			"id": "file--c7d1e135-8b34-549a-bb47-302f5cf998ed",
			"name": "picture.jpg",
			"hashes": {
			  "SHA-256": "4bac27393bdd9777ce02453256c5577cd02275510b2227f473d03f533924f877"
			},
			"extensions": {
			  "raster-image-ext": {
				"exif_tags": {
				  "Make": "Nikon",
				  "Model": "D7000",
				  "XResolution": 4928,
				  "YResolution": 3264
				}
			  }
			}
		  }
`)

		var obj *File
		err := json.Unmarshal(data, &obj)
		assert.NoError(err)

		ext := obj.RasterImageExtension()
		assert.NotNil(ext)
		assert.Equal("Nikon", ext.ExifTags["Make"])
		assert.Equal(float64(4928), ext.ExifTags["XResolution"])
	})

	t.Run("return-nil-on-empty-extension", func(t *testing.T) {
		f := &File{}

		e := f.ArchiveExtension()
		assert.Nil(e)
		f.NTFSExtension()
		assert.Nil(e)
		f.PDFExtension()
		assert.Nil(e)
		f.RasterImageExtension()
		assert.Nil(e)
		f.WindowsPEBinaryExtension()
		assert.Nil(e)
	})
}
