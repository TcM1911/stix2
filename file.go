// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import (
	"fmt"
	"strings"
)

// File object represents the properties of a file. A File object MUST contain
// at least one of hashes or name.
type File struct {
	STIXCyberObservableObject
	// Hashes specifies a dictionary of hashes for the file.
	Hashes Hashes `json:"hashes,omitempty"`
	// Size specifies the size of the file, in bytes. The value of this
	// property MUST NOT be negative.
	Size int64 `json:"size,omitempty"`
	// Name specifies the name of the file.
	Name string `json:"name,omitempty"`
	// NameEnc specifies the observed encoding for the name of the file. This
	// value MUST be specified using the corresponding name from the 2013-12-20
	// revision of the IANA character set registry. If the value from the
	// Preferred MIME Name column for a character set is defined, this value
	// MUST be used; if it is not defined, then the value from the Name column
	// in the registry MUST be used instead.
	NameEnc string `json:"name_enc,omitempty"`
	// MagicNumber specifies the hexadecimal constant (“magic number”)
	// associated with a specific file format that corresponds to the file, if
	// applicable.
	MagicNumber Hex `json:"magic_number_hex,omitempty"`
	// MimeType specifies the MIME type name specified for the file, e.g.,
	// application/msword.
	MimeType string `json:"mime_type,omitempty"`
	// Ctime specifies the date/time the file was created.
	Ctime *Timestamp `json:"ctime,omitempty"`
	// Mtime specifies the date/time the file was last written to/modified.
	Mtime *Timestamp `json:"mtime,omitempty"`
	// Atime specifies the date/time the file was last accessed.
	Atime *Timestamp `json:"atime,omitempty"`
	// ParentDirectory specifies the parent directory of the file, as a
	// reference to a Directory object.
	ParentDirectory Identifier `json:"parent_directory_ref,omitempty"`
	// Contains specifies a list of references to other Cyber-observable
	// Objects contained within the file, such as another file that is appended
	// to the end of the file, or an IP address that is contained somewhere in
	// the file.
	Contains []Identifier `json:"contains_refs,omitempty"`
	// Content specifies the content of the file, represented as an Artifact
	// object.
	Content Identifier `json:"content_ref,omitempty"`
}

// ArchiveExtension returns the archive extension for the object or nil.
func (f *File) ArchiveExtension() *ArchiveFileExtension {
	data, ok := f.Extensions[ExtArchive]
	if !ok {
		return nil
	}
	return data.(*ArchiveFileExtension)
}

// NTFSExtension returns the NTFS extension for the object or nil.
func (f *File) NTFSExtension() *NTFSFileExtension {
	data, ok := f.Extensions[ExtNTFS]
	if !ok {
		return nil
	}
	return data.(*NTFSFileExtension)
}

// PDFExtension returns the PDF extension for the object or nil.
func (f *File) PDFExtension() *PDFExtension {
	data, ok := f.Extensions[ExtPDF]
	if !ok {
		return nil
	}
	return data.(*PDFExtension)
}

// RasterImageExtension returns the raster image extension for the object or nil.
func (f *File) RasterImageExtension() *RasterImageExtension {
	data, ok := f.Extensions[ExtRasterImage]
	if !ok {
		return nil
	}
	return data.(*RasterImageExtension)
}

// WindowsPEBinaryExtension returns the Windows PE binary extension for the
// object or nil.
func (f *File) WindowsPEBinaryExtension() *WindowsPEBinaryExtension {
	data, ok := f.Extensions[ExtWindowsPEBinary]
	if !ok {
		return nil
	}
	return data.(*WindowsPEBinaryExtension)
}

// NewFile creates a new File object. A File object MUST contain at least one
// of hashes or name.
func NewFile(name string, hashes Hashes, opts ...STIXOption) (*File, error) {
	if name == "" && hashes == nil {
		return nil, ErrInvalidParameter
	}
	base := newSTIXCyberObservableObject(TypeFile)
	obj := &File{
		STIXCyberObservableObject: base,
		Name:                      name,
		Hashes:                    hashes,
	}

	err := applyOptions(obj, opts)
	idContri := make([]string, 0, 4)
	if len(obj.Hashes) != 0 {
		idContri = append(idContri, obj.Hashes.getIDContribution())
	}
	if obj.Name != "" {
		idContri = append(idContri, fmt.Sprintf(`"%s"`, obj.Name))
	}
	if len(obj.Extensions) != 0 {
		idContri = append(idContri, obj.canonicalizeExtensions())
	}
	if obj.ParentDirectory != "" {
		idContri = append(idContri, fmt.Sprintf(`"%s"`, obj.ParentDirectory))
	}
	obj.ID = NewObservableIdentifier(fmt.Sprintf("[%s]", strings.Join(idContri, ",")), TypeFile)
	return obj, err
}

// ArchiveFileExtension specifies a default extension for capturing properties
// specific to archive files. The key for this extension when used in the
// extensions dictionary MUST be archive-ext.
type ArchiveFileExtension struct {
	// Contains specifies the files that are contained in the archive. It MUST
	// contain references to one or more File objects.
	Contains []Identifier `json:"contains_refs"`
	// Comment specifies a comment included as part of the archive file.
	Comment string `json:"comment,omitempty"`
}

// NTFSFileExtension specifies a default extension for capturing properties
// specific to the storage of the file on the NTFS file system. The key for
// this extension when used in the extensions dictionary MUST be ntfs-ext. An
// object using the NTFS File Extension MUST contain at least one property from
// this extension.
type NTFSFileExtension struct {
	// SID specifies the security ID (SID) value assigned to the file.
	SID string `json:"sid,omitempty"`
	// AltDataStreams specifies a list of NTFS alternate data streams that
	// exist for the file.
	AltDataStreams []AltDataStream `json:"alternate_data_streams,omitempty"`
}

// AltDataStream represents an NTFS alternate data stream.
type AltDataStream struct {
	// Name specifies the name of the alternate data stream.
	Name string `json:"name"`
	// Hashes specifies a dictionary of hashes for the data contained in the
	// alternate data stream.
	Hashes Hashes `json:"hashes,omitempty"`
	// Size specifies the size of the alternate data stream, in bytes.
	Size int64 `json:"size,omitempty"`
}

// PDFExtension specifies a default extension for capturing properties specific
// to PDF files. The key for this extension when used in the extensions
// dictionary MUST be pdf-ext. An object using the PDF File Extension MUST
// contain at least one property from this extension.
type PDFExtension struct {
	// Version specifies the decimal version number of the string from the PDF
	// header that specifies the version of the PDF specification to which the
	// PDF file conforms. E.g., 1.4.
	Version string `json:"version,omitempty"`
	// IsOptimized specifies whether the PDF file has been optimized.
	IsOptimized bool `json:"is_optimized,omitempty"`
	// DocumentInfo specifies details of the PDF document information dictionary
	// (DID), which includes properties like the document creation data and
	// producer, as a dictionary. Each key in the dictionary SHOULD be a
	// case-preserved version of the corresponding entry in the document
	// information dictionary without the prepended forward slash, e.g., Title.
	// The corresponding value for the key MUST be the value specified for the
	// document information dictionary entry, as a string.
	DocumentInfo map[string]string `json:"document_info_dict,omitempty"`
	// PDFid0 specifies the first file identifier found for the PDF file.
	PDFid0 string `json:"pdfid0,omitempty"`
	// PDFid1 specifies the second file identifier found for the PDF file.
	PDFid1 string `json:"pdfid1,omitempty"`
}

// RasterImageExtension specifies a default extension for capturing properties
// specific to raster image files. The key for this extension when used in the
// extensions dictionary MUST be raster-image-ext. An object using the Raster
// Image File Extension MUST contain at least one property from this extension.
type RasterImageExtension struct {
	// Height specifies the height of the image in the image file, in pixels.
	Height int64 `json:"image_height,omitempty"`
	// Width specifies the width of the image in the image file, in pixels.
	Width int64 `json:"image_width,omitempty"`
	// BitsPerPixel specifies the sum of bits used for each color channel in
	// the image file, and thus the total number of pixels used for expressing
	// the color depth of the image.
	BitsPerPixel int64 `json:"bits_per_pixel,omitempty"`
	// ExifTags specifies the set of EXIF tags found in the image file, as a
	// dictionary. Each key/value pair in the dictionary represents the
	// name/value of a single EXIF tag. Accordingly, each dictionary key MUST
	// be a case-preserved version of the EXIF tag name, e.g., XResolution.
	// Each dictionary value MUST be either an integer (for int* EXIF
	// datatypes) or a string (for all other EXIF datatypes).
	ExifTags map[string]interface{} `json:"exif_tags,omitempty"`
}

// WindowsPEBinaryExtension specifies a default extension for capturing
// properties specific to Windows portable executable (PE) files. The key for
// this extension when used in the extensions dictionary MUST be
// windows-pebinary-ext. An object using the Windows™ PE Binary File Extension
// MUST contain at least one property other than the required PEType property
// from this extension.
type WindowsPEBinaryExtension struct {
	// PEType specifies the type of the PE binary.
	PEType WindowsPEBinaryType `json:"pe_type"`
	// ImpHash specifies the special import hash, or ‘imphash’, calculated for
	// the PE Binary based on its imported libraries and functions.
	ImpHash string `json:"imphash,omitempty"`
	// Machine specifies the type of target machine.
	Machine Hex `json:"machine_hex,omitempty"`
	// NumberOfSections specifies the number of sections in the PE binary, as a
	// non-negative integer.
	NumberOfSections int64 `json:"number_of_sections,omitempty"`
	// TimeDateStamp specifies the time when the PE binary was created. The
	// timestamp value MUST be precise to the second.
	TimeDateStamp *Timestamp `json:"time_date_stamp,omitempty"`
	// PointerToSymbolTable specifies the file offset of the COFF symbol table.
	PointerToSymbolTable Hex `json:"pointer_to_symbol_table_hex,omitempty"`
	// NumberOfSymbols specifies the number of entries in the symbol table of
	// the PE binary, as a non-negative integer.
	NumberOfSymbols int64 `json:"number_of_symbols,omitempty"`
	// SizeOfOptionalHeader specifies the size of the optional header of the PE
	// binary. The value of this property MUST NOT be negative.
	SizeOfOptionalHeader int64 `json:"size_of_optional_header,omitempty"`
	// Characteristics specifies the flags that indicate the file’s
	// characteristics.
	Characteristics Hex `json:"characteristics_hex,omitempty"`
	// FileHeaderHash specifies any hashes that were computed for the file
	// header.
	FileHeaderHash Hashes `json:"file_header_hashes,omitempty"`
	// OptionalHeader specifies the PE optional header of the PE binary.
	OptionalHeader WindowsPEOptionalHeader `json:"optional_header,omitempty"`
	// Sections specifies metadata about the sections in the PE file.
	Sections []WindowsPESection `json:"sections,omitempty"`
}

// WindowsPEBinaryType is a PE binary type.
type WindowsPEBinaryType string

const (
	// WindowsPEDLL specifies that the PE binary is a dynamically linked
	// library (DLL).
	WindowsPEDLL WindowsPEBinaryType = "dll"
	// WindowsPEExe specifies that the PE binary is an executable image (i.e.,
	// not an OBJ or DLL).
	WindowsPEExe WindowsPEBinaryType = "exe"
	// WindowsPESys specifies that the PE binary is a device driver (SYS).
	WindowsPESys WindowsPEBinaryType = "sys"
)

// WindowsPEOptionalHeader represents the properties of the PE optional header.
// An object using the Windows PE Optional Header Type MUST contain at least
// one property from this type.
type WindowsPEOptionalHeader struct {
	// Magic specifies the hex value that indicates the type of the PE binary.
	Magic Hex `json:"magic_hex,omitempty"`
	// MajorLinkerVersion specifies the linker major version number.
	MajorLinkerVersion int64 `json:"major_linker_version,omitempty"`
	// MinorLinkerVersion specifies the linker minor version number.
	MinorLinkerVersion int64 `json:"minor_linker_version,omitempty"`
	// SizeOfCode specifies the size of the code (text) section. If there are
	// multiple such sections, this refers to the sum of the sizes of each
	// section. The value of this property MUST NOT be negative.
	SizeOfCode int64 `json:"size_of_code,omitempty"`
	// SizeOfInitializedData specifies the size of the initialized data section.
	// If there are multiple such sections, this refers to the sum of the sizes
	// of each section. The value of this property MUST NOT be negative.
	SizeOfInitializedData int64 `json:"size_of_initialized_data,omitempty"`
	// SizeOfUninitializedData specifies the size of the uninitialized data
	// section. If there are multiple such sections, this refers to the sum of
	// the sizes of each section. The value of this property MUST NOT be
	// negative.
	SizeOfUninitializedData int64 `json:"size_of_uninitialized_data,omitempty"`
	// AddressOfEntryPoint specifies the address of the entry point relative to
	// the image base when the executable is loaded into memory.
	AddressOfEntryPoint int64 `json:"address_of_entry_point,omitempty"`
	// BaseOfCode specifies the address that is relative to the image base of
	// the beginning-of-code section when it is loaded into memory.
	BaseOfCode int64 `json:"base_of_code,omitempty"`
	// BaseOfData specifies the address that is relative to the image base of
	// the beginning-of-data section when it is loaded into memory.
	BaseOfData int64 `json:"base_of_data,omitempty"`
	// ImageBase specifies the preferred address of the first byte of the image
	// when loaded into memory.
	ImageBase int64 `json:"image_base,omitempty"`
	// SectionAlignment specifies the alignment (in bytes) of PE sections when
	// they are loaded into memory.
	SectionAlignment int64 `json:"section_alignment,omitempty"`
	// FileAlignment specifies the factor (in bytes) that is used to align the
	// raw data of sections in the image file.
	FileAlignment int64 `json:"file_alignment,omitempty"`
	// MajorOSVersion specifies the major version number of the required
	// operating system.
	MajorOSVersion int64 `json:"major_os_version,omitempty"`
	// MinorOSVersion specifies the minor version number of the required
	// operating system.
	MinorOSVersion int64 `json:"minor_os_version,omitempty"`
	// MajorImageVersion specifies the major version number of the image.
	MajorImageVersion int64 `json:"major_image_version,omitempty"`
	// MinorImageVersion specifies the minor version number of the image.
	MinorImageVersion int64 `json:"minor_image_version,omitempty"`
	// MajorSubsystemVersion specifies the major version number of the
	// subsystem.
	MajorSubsystemVersion int64 `json:"major_subsystem_version,omitempty"`
	// MinorSubsystemVersion specifies the minor version number of the
	// subsystem.
	MinorSubsystemVersion int64 `json:"minor_subsystem_version,omitempty"`
	// Win32VersionValue specifies the reserved win32 version value.
	Win32VersionValue Hex `json:"win32_version_value_hex,omitempty"`
	// SizeOfImage specifies the size of the image in bytes, including all
	// headers, as the image is loaded in memory. The value of this property
	// MUST NOT be negative.
	SizeOfImage int64 `json:"size_of_image,omitempty"`
	// SizeOfHeaders specifies the combined size of the MS-DOS, PE header, and
	// section headers, rounded up to a multiple of the value specified in the
	// file_alignment header. The value of this property MUST NOT be negative.
	SizeOfHeaders int64 `json:"size_of_headers"`
	// Checksum specifies the checksum of the PE binary.
	Checksum Hex `json:"checksum_hex,omitempty"`
	// Subsystem specifies the subsystem (e.g., GUI, device driver, etc.) that
	// is required to run this image.
	Subsystem Hex `json:"subsystem_hex,omitempty"`
	// DLLCharacteristics specifies the flags that characterize the PE binary.
	DLLCharacteristics Hex `json:"dll_characteristics_hex,omitempty"`
	// SizeOfStackReserve specifies the size of the stack to reserve, in bytes.
	// The value of this property MUST NOT be negative.
	SizeOfStackReserve int64 `json:"size_of_stack_reserve,omitempty"`
	// SizeOfStackCommit specifies the size of the stack to commit, in bytes.
	// The value of this property MUST NOT be negative.
	SizeOfStackCommit int64 `json:"size_of_stack_commit,omitempty"`
	// SizeOfHeapReserve specifies the size of the local heap space to reserve,
	// in bytes. The value of this property MUST NOT be negative.
	SizeOfHeapReserve int64 `json:"size_of_heap_reserve,omitempty"`
	// SizeOfHeapCommit specifies the size of the local heap space to commit,
	// in bytes. The value of this property MUST NOT be negative.
	SizeOfHeapCommit int64 `json:"size_of_heap_commit,omitempty"`
	// LoaderFlags specifies the reserved loader flags.
	LoaderFlags Hex `json:"loader_flags_hex,omitempty"`
	// NumberOfRVAAndSizes specifies the number of data-directory entries in
	// the remainder of the optional header.
	NumberOfRVAAndSizes int64 `json:"number_of_rva_and_sizes,omitempty"`
	// Hashes specifies any hashes that were computed for the optional header.
	Hashes Hashes `json:"hashes,omitempty"`
}

// WindowsPESection specifies metadata about a PE file section.
type WindowsPESection struct {
	// Name specifies the name of the section.
	Name string `json:"name"`
	// Size specifies the size of the section, in bytes. The value of this
	// property MUST NOT be negative.
	Size int64 `json:"size,omitempty"`
	// Entropy specifies the calculated entropy for the section, as calculated
	// using the Shannon algorithm
	// (https://en.wiktionary.org/wiki/Shannon_entropy). The size of each input
	// character is defined as a byte, resulting in a possible range of 0
	// through 8.
	Entropy float64 `json:"entropy,omitempty"`
	// Hashes specifies any hashes computed over the section.
	Hashes Hashes `json:"hashes,omitempty"`
}
