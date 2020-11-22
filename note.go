// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

// Note is intended to convey informative text to provide further context
// and/or to provide additional analysis not contained in the STIX Objects,
// Marking Definition objects, or Language Content objects which the Note
// relates to. Notes can be created by anyone (not just the original object
// creator). For example, an analyst may add a Note to a Campaign object
// created by another organization indicating that they've seen posts related
// to that Campaign on a hacker forum. Because Notes are typically (though not
// always) created by human analysts and are comprised of human-oriented text,
// they contain an additional property to capture the analyst(s) that created
// the Note. This is distinct from the created_by_ref property, which is meant
// to capture the organization that created the object.
type Note struct {
	STIXDomainObject
	// Abstract is a brief summary of the note content.
	Abstract string `json:"abstract,omitempty"`
	// Content is the content of the note.
	Content string `json:"content"`
	// Authors is/are the name of the author(s) of this note (e.g., the
	// analyst(s) that created it).
	Authors []string `json:"authors,omitempty"`
	// Objects are the STIX Objects that the note is being applied to.
	Objects []Identifier `json:"object_refs"`
}

// NewNote creates a new Note object.
func NewNote(content string, objects []Identifier, opts ...STIXOption) (*Note, error) {
	if len(objects) == 0 {
		return nil, ErrPropertyMissing
	}
	base := newSTIXDomainObject(TypeNote)
	obj := &Note{
		STIXDomainObject: base,
		Content:          content,
		Objects:          objects,
	}

	err := applyOptions(obj, opts)
	return obj, err
}
