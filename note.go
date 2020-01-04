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
	*STIXDomainObject
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
func NewNote(content string, objects []Identifier, opts ...NoteOption) (*Note, error) {
	if len(objects) == 0 {
		return nil, ErrPropertyMissing
	}
	base, err := newSTIXDomainObject(TypeNote)
	if err != nil {
		return nil, err
	}
	obj := &Note{
		STIXDomainObject: base,
		Content:          content,
		Objects:          objects,
	}

	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(obj)
	}
	return obj, nil
}

// NoteOption is an optional parameter when constructing a
// Note object.
type NoteOption func(a *Note)

/*
	Base object options
*/

// NoteOptionSpecVersion sets the STIX spec version.
func NoteOptionSpecVersion(ver string) NoteOption {
	return func(obj *Note) {
		obj.SpecVersion = ver
	}
}

// NoteOptionExternalReferences sets the external references attribute.
func NoteOptionExternalReferences(refs []*ExternalReference) NoteOption {
	return func(obj *Note) {
		obj.ExternalReferences = refs
	}
}

// NoteOptionObjectMarking sets the object marking attribute.
func NoteOptionObjectMarking(om []Identifier) NoteOption {
	return func(obj *Note) {
		obj.ObjectMarking = om
	}
}

// NoteOptionGranularMarking sets the granular marking attribute.
func NoteOptionGranularMarking(gm *GranularMarking) NoteOption {
	return func(obj *Note) {
		obj.GranularMarking = gm
	}
}

// NoteOptionLang sets the lang attribute.
func NoteOptionLang(lang string) NoteOption {
	return func(obj *Note) {
		obj.Lang = lang
	}
}

// NoteOptionConfidence sets the confidence attribute.
func NoteOptionConfidence(confidence int) NoteOption {
	return func(obj *Note) {
		obj.Confidence = confidence
	}
}

// NoteOptionLables sets the lables attribute.
func NoteOptionLables(lables []string) NoteOption {
	return func(obj *Note) {
		obj.Lables = lables
	}
}

// NoteOptionRevoked sets the revoked attribute.
func NoteOptionRevoked(rev bool) NoteOption {
	return func(obj *Note) {
		obj.Revoked = rev
	}
}

// NoteOptionModified sets the modified attribute.
func NoteOptionModified(t *Timestamp) NoteOption {
	return func(obj *Note) {
		obj.Modified = t
	}
}

// NoteOptionCreated sets the created attribute.
func NoteOptionCreated(t *Timestamp) NoteOption {
	return func(obj *Note) {
		obj.Created = t
	}
}

// NoteOptionCreatedBy sets the created by by attribute.
func NoteOptionCreatedBy(id Identifier) NoteOption {
	return func(obj *Note) {
		obj.CreatedBy = id
	}
}

/*
	Note object options
*/

// NoteOptionAbstract sets the abstract attribute.
func NoteOptionAbstract(s string) NoteOption {
	return func(obj *Note) {
		obj.Abstract = s
	}
}

// NoteOptionAuthors sets the authors attribute.
func NoteOptionAuthors(s []string) NoteOption {
	return func(obj *Note) {
		obj.Authors = s
	}
}
