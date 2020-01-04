// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import (
	"fmt"
	"strings"
)

// EmailAddress object represents a single email address.
type EmailAddress struct {
	*STIXCyberObservableObject
	// Value specifies the value of the email address. This MUST NOT include
	// the display name.
	Value string `json:"value"`
	// DisplayName specifies a single email display name, i.e., the name that
	// is displayed to the human user of a mail application.
	DisplayName string `json:"display_name,omitempty"`
	// BelongsTo specifies the user account that the email address belongs to,
	// as a reference to a User Account object.
	BelongsTo Identifier `json:"belongs_to_ref,omitempty"`
}

// NewEmailAddress creates a new EmailAddress object.
func NewEmailAddress(value string, opts ...EmailAddressOption) (*EmailAddress, error) {
	if value == "" {
		return nil, ErrInvalidParameter
	}
	base := newSTIXCyberObservableObject(TypeEmailAddress)
	obj := &EmailAddress{
		STIXCyberObservableObject: base,
		Value:                     value,
	}

	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(obj)
	}
	obj.ID = NewObservableIdenfier(fmt.Sprintf("[\"%s\"]", value), TypeEmailAddress)
	return obj, nil
}

// EmailAddressOption is an optional parameter when constructing a
// EmailAddress object.
type EmailAddressOption func(a *EmailAddress)

/*
	Base object options
*/

// EmailAddressOptionSpecVersion sets the STIX spec version.
func EmailAddressOptionSpecVersion(ver string) EmailAddressOption {
	return func(obj *EmailAddress) {
		obj.SpecVersion = ver
	}
}

// EmailAddressOptionObjectMarking sets the object marking attribute.
func EmailAddressOptionObjectMarking(om []Identifier) EmailAddressOption {
	return func(obj *EmailAddress) {
		obj.ObjectMarking = om
	}
}

// EmailAddressOptionGranularMarking sets the granular marking attribute.
func EmailAddressOptionGranularMarking(gm *GranularMarking) EmailAddressOption {
	return func(obj *EmailAddress) {
		obj.GranularMarking = gm
	}
}

// EmailAddressOptionDefanged sets the defanged attribute.
func EmailAddressOptionDefanged(b bool) EmailAddressOption {
	return func(obj *EmailAddress) {
		obj.Defanged = b
	}
}

// EmailAddressOptionExtension adds an extension.
func EmailAddressOptionExtension(name string, value interface{}) EmailAddressOption {
	return func(obj *EmailAddress) {
		// Ignoring the error.
		obj.addExtension(name, value)
	}
}

/*
	EmailAddress object options
*/

// EmailAddressOptionDisplayName sets the display name attribute.
func EmailAddressOptionDisplayName(s string) EmailAddressOption {
	return func(obj *EmailAddress) {
		obj.DisplayName = s
	}
}

// EmailAddressOptionBelongsTo sets the belongs to attribute.
func EmailAddressOptionBelongsTo(s Identifier) EmailAddressOption {
	return func(obj *EmailAddress) {
		obj.BelongsTo = s
	}
}

// EmailMessage rrepresents an instance of an email message, corresponding to
// the internet message format described in RFC5322 and related RFCs. Header
// field values that have been encoded as described in section 2 of RFC2047
// MUST be decoded before inclusion in Email Message object properties. For
// example, this is some text MUST be used instead of
// =?iso-8859-1?q?this=20is=20some=20text?=. Any characters in the encoded
// value which cannot be decoded into Unicode SHOULD be replaced with the
// 'REPLACEMENT CHARACTER' (U+FFFD). If it is necessary to capture the header
// value as observed, this can be achieved by referencing an Artifact object
// through the raw_email_ref property.
type EmailMessage struct {
	*STIXCyberObservableObject
	// IsMultipart indicates whether the email body contains multiple MIME
	// parts.
	IsMultipart bool `json:"is_multipart"`
	// Date specifies the date/time that the email message was sent.
	Date *Timestamp `json:"date,omitempty"`
	// ContentType specifies the value of the “Content-Type” header of the
	// email message.
	ContentType string `json:"content_type,omitempty"`
	// From specifies the value of the “From:” header of the email message. The
	// "From:" field specifies the author of the message, that is, the
	// mailbox(es) of the person or system responsible for the writing of the
	// message.
	From Identifier `json:"from_ref,omitempty"`
	// Sender specifies the value of the “Sender” field of the email message.
	// The "Sender:" field specifies the mailbox of the agent responsible for
	// the actual transmission of the message.
	Sender Identifier `json:"sender_ref,omitempty"`
	// To pecifies the mailboxes that are “To:” recipients of the email
	// message.
	To []Identifier `json:"to_refs,omitempty"`
	// CC specifies the mailboxes that are “CC:” recipients of the email
	// message.
	CC []Identifier `json:"cc_refs,omitempty"`
	// BCC specifies the mailboxes that are “BCC:” recipients of the email
	// message.
	BCC []Identifier `json:"bcc_refs,omitempty"`
	// MessageID specifies the Message-ID field of the email message.
	MessageID string `json:"message_id,omitempty"`
	// Subject specifies the subject of the email message.
	Subject string `json:"subject,omitempty"`
	// ReceivedLines specifies one or more "Received" header fields that may be
	// included in the email headers.
	ReceivedLines []string `json:"received_lines,omitempty"`
	// AdditionalHeaderFields specifies any other header fields (except for
	// date, received_lines, content_type, from_ref, sender_ref, to_refs,
	// cc_refs, bcc_refs, and subject) found in the email message.
	AdditionalHeaderFields map[string]string `json:"additional_header_fields,omitempty"`
	// Body specifies a string containing the email body. This property MUST
	// NOT be used if IsMultipart is true.
	Body string `json:"body,omitempty"`
	// BodyMultipart specifies a list of the MIME parts that make up the email
	// body. This property MUST NOT be used if IsMultipart is false.
	BodyMultipart []EmailMIME `json:"body_multipart,omitempty"`
	// RawEmail specifies the raw binary contents of the email message,
	// including both the headers and body, as a reference to an Artifact
	// object.
	RawEmail Identifier `json:"raw_email_ref,omitempty"`
}

// NewEmailMessage creates a new EmailMessage object.
func NewEmailMessage(multipart bool, opts ...EmailMessageOption) (*EmailMessage, error) {
	base := newSTIXCyberObservableObject(TypeEmailMessage)
	obj := &EmailMessage{
		STIXCyberObservableObject: base,
		IsMultipart:               multipart,
	}

	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(obj)
	}
	idContri := make([]string, 0, 3)
	if obj.From != "" {
		idContri = append(idContri, fmt.Sprintf(`"%s"`, obj.From))
	}
	if obj.Subject != "" {
		idContri = append(idContri, fmt.Sprintf(`"%s"`, obj.Subject))
	}
	if obj.Body != "" {
		idContri = append(idContri, fmt.Sprintf(`"%s"`, obj.Body))
	}
	obj.ID = NewObservableIdenfier(fmt.Sprintf("[%s]", strings.Join(idContri, ",")), TypeEmailMessage)
	return obj, nil
}

// EmailMessageOption is an optional parameter when constructing a
// EmailMessage object.
type EmailMessageOption func(a *EmailMessage)

/*
	Base object options
*/

// EmailMessageOptionSpecVersion sets the STIX spec version.
func EmailMessageOptionSpecVersion(ver string) EmailMessageOption {
	return func(obj *EmailMessage) {
		obj.SpecVersion = ver
	}
}

// EmailMessageOptionObjectMarking sets the object marking attribute.
func EmailMessageOptionObjectMarking(om []Identifier) EmailMessageOption {
	return func(obj *EmailMessage) {
		obj.ObjectMarking = om
	}
}

// EmailMessageOptionGranularMarking sets the granular marking attribute.
func EmailMessageOptionGranularMarking(gm *GranularMarking) EmailMessageOption {
	return func(obj *EmailMessage) {
		obj.GranularMarking = gm
	}
}

// EmailMessageOptionDefanged sets the defanged attribute.
func EmailMessageOptionDefanged(b bool) EmailMessageOption {
	return func(obj *EmailMessage) {
		obj.Defanged = b
	}
}

// EmailMessageOptionExtension adds an extension.
func EmailMessageOptionExtension(name string, value interface{}) EmailMessageOption {
	return func(obj *EmailMessage) {
		// Ignoring the error.
		obj.addExtension(name, value)
	}
}

/*
	EmailMessage object options
*/

// EmailMessageOptionDate sets the date attribute.
func EmailMessageOptionDate(s *Timestamp) EmailMessageOption {
	return func(obj *EmailMessage) {
		obj.Date = s
	}
}

// EmailMessageOptionContentType sets the content type attribute.
func EmailMessageOptionContentType(s string) EmailMessageOption {
	return func(obj *EmailMessage) {
		obj.ContentType = s
	}
}

// EmailMessageOptionFrom sets the from attribute.
func EmailMessageOptionFrom(s Identifier) EmailMessageOption {
	return func(obj *EmailMessage) {
		obj.From = s
	}
}

// EmailMessageOptionSender sets the sender attribute.
func EmailMessageOptionSender(s Identifier) EmailMessageOption {
	return func(obj *EmailMessage) {
		obj.Sender = s
	}
}

// EmailMessageOptionTo sets the to attribute.
func EmailMessageOptionTo(s []Identifier) EmailMessageOption {
	return func(obj *EmailMessage) {
		obj.To = s
	}
}

// EmailMessageOptionCC sets the CC attribute.
func EmailMessageOptionCC(s []Identifier) EmailMessageOption {
	return func(obj *EmailMessage) {
		obj.CC = s
	}
}

// EmailMessageOptionBCC sets the BCC attribute.
func EmailMessageOptionBCC(s []Identifier) EmailMessageOption {
	return func(obj *EmailMessage) {
		obj.BCC = s
	}
}

// EmailMessageOptionMessageID sets the message ID attribute.
func EmailMessageOptionMessageID(s string) EmailMessageOption {
	return func(obj *EmailMessage) {
		obj.MessageID = s
	}
}

// EmailMessageOptionSubject sets the subject attribute.
func EmailMessageOptionSubject(s string) EmailMessageOption {
	return func(obj *EmailMessage) {
		obj.Subject = s
	}
}

// EmailMessageOptionReceivedLines sets the received lines attribute.
func EmailMessageOptionReceivedLines(s []string) EmailMessageOption {
	return func(obj *EmailMessage) {
		obj.ReceivedLines = s
	}
}

// EmailMessageOptionAdditionalHeaderFields sets the additional header fields
// attribute.
func EmailMessageOptionAdditionalHeaderFields(s map[string]string) EmailMessageOption {
	return func(obj *EmailMessage) {
		obj.AdditionalHeaderFields = s
	}
}

// EmailMessageOptionBody sets the body attribute.
func EmailMessageOptionBody(s string) EmailMessageOption {
	return func(obj *EmailMessage) {
		obj.Body = s
	}
}

// EmailMessageOptionBodyMultipart sets the body multipart attribute.
func EmailMessageOptionBodyMultipart(s []EmailMIME) EmailMessageOption {
	return func(obj *EmailMessage) {
		obj.BodyMultipart = s
	}
}

// EmailMessageOptionRawEmail sets the raw email attribute.
func EmailMessageOptionRawEmail(s Identifier) EmailMessageOption {
	return func(obj *EmailMessage) {
		obj.RawEmail = s
	}
}

// EmailMIME specifies one component of a multi-part email body.
type EmailMIME struct {
	// Body specifies the contents of the MIME part if the content_type is not
	// provided or starts with text/ (e.g., in the case of plain text or HTML
	// email).
	Body string `json:"body,omitempty"`
	// BodyRaw specifies the contents of non-textual MIME parts, that is those
	// whose content_type does not start with text/, as a reference to an
	// Artifact object or File object.
	BodyRaw Identifier `json:"body_raw_ref,omitempty"`
	// ContentType specifies the value of the “Content-Type” header field of
	// the MIME part.
	ContentType string `json:"content_type,omitempty"`
	// ContentDisposition specifies the value of the “Content-Disposition”
	// header field of the MIME part.
	ContentDisposition string `json:"content_disposition,omitempty"`
}
