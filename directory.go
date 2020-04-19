// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import "fmt"

// Directory object represents the properties common to a file system
// directory.
type Directory struct {
	STIXCyberObservableObject
	// Path specifies the path, as originally observed, to the directory on the
	// file system.
	Path string `json:"path"`
	// PathEnc specifies the observed encoding for the path. The value MUST be
	// specified if the path is stored in a non-Unicode encoding. This value
	// MUST be specified using the corresponding name from the 2013-12-20
	// revision of the IANA character set registry. If the preferred MIME name
	// for a character set is defined, this value MUST be used; if it is not
	// defined, then the Name value from the registry MUST be used instead.
	PathEnc string `json:"path_enc,omitempty"`
	// Ctime specifies the date/time the directory was created.
	Ctime *Timestamp `json:"ctime,omitempty"`
	// Mtime specifies the date/time the directory was last written
	// to/modified.
	Mtime *Timestamp `json:"mtime,omitempty"`
	// Atime specifies the date/time the directory was last accessed.
	Atime *Timestamp `json:"atime,omitempty"`
	// Contains specifies a list of references to other File and/or Directory
	// objects contained within the directory.
	Contains []Identifier `json:"contains_refs,omitempty"`
}

// NewDirectory creates a new Directory object.
func NewDirectory(path string, opts ...DirectoryOption) (*Directory, error) {
	if path == "" {
		return nil, ErrInvalidParameter
	}
	base := newSTIXCyberObservableObject(TypeDirectory)
	obj := &Directory{
		STIXCyberObservableObject: base,
		Path:                      path,
	}

	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(obj)
	}
	obj.ID = NewObservableIdenfier(fmt.Sprintf("[\"%s\"]", path), TypeDirectory)
	return obj, nil
}

// DirectoryOption is an optional parameter when constructing a
// Directory object.
type DirectoryOption func(a *Directory)

/*
	Base object options
*/

// DirectoryOptionSpecVersion sets the STIX spec version.
func DirectoryOptionSpecVersion(ver string) DirectoryOption {
	return func(obj *Directory) {
		obj.SpecVersion = ver
	}
}

// DirectoryOptionObjectMarking sets the object marking attribute.
func DirectoryOptionObjectMarking(om []Identifier) DirectoryOption {
	return func(obj *Directory) {
		obj.ObjectMarking = om
	}
}

// DirectoryOptionGranularMarking sets the granular marking attribute.
func DirectoryOptionGranularMarking(gm []*GranularMarking) DirectoryOption {
	return func(obj *Directory) {
		obj.GranularMarking = gm
	}
}

// DirectoryOptionDefanged sets the defanged attribute.
func DirectoryOptionDefanged(b bool) DirectoryOption {
	return func(obj *Directory) {
		obj.Defanged = b
	}
}

// DirectoryOptionExtension adds an extension.
func DirectoryOptionExtension(name string, value interface{}) DirectoryOption {
	return func(obj *Directory) {
		// Ignoring the error.
		obj.addExtension(name, value)
	}
}

/*
	Directory object options
*/

// DirectoryOptionPathEncoding sets the path encoding attribute.
func DirectoryOptionPathEncoding(s string) DirectoryOption {
	return func(obj *Directory) {
		obj.PathEnc = s
	}
}

// DirectoryOptionCtime sets the ctime attribute.
func DirectoryOptionCtime(s *Timestamp) DirectoryOption {
	return func(obj *Directory) {
		obj.Ctime = s
	}
}

// DirectoryOptionMtime sets the mtime attribute.
func DirectoryOptionMtime(s *Timestamp) DirectoryOption {
	return func(obj *Directory) {
		obj.Mtime = s
	}
}

// DirectoryOptionAtime sets the atime attribute.
func DirectoryOptionAtime(s *Timestamp) DirectoryOption {
	return func(obj *Directory) {
		obj.Atime = s
	}
}

// DirectoryOptionContains sets the contains attribute.
func DirectoryOptionContains(s []Identifier) DirectoryOption {
	return func(obj *Directory) {
		obj.Contains = s
	}
}
