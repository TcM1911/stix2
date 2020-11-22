// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import (
	"fmt"
	"strings"
)

// EmailAddress object represents a single email address.
type EmailAddress struct {
	STIXCyberObservableObject
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
func NewEmailAddress(value string, opts ...STIXOption) (*EmailAddress, error) {
	if value == "" {
		return nil, ErrInvalidParameter
	}
	base := newSTIXCyberObservableObject(TypeEmailAddress)
	obj := &EmailAddress{
		STIXCyberObservableObject: base,
		Value:                     value,
	}

	err := applyOptions(obj, opts)
	obj.ID = NewObservableIdenfier(fmt.Sprintf("[\"%s\"]", value), TypeEmailAddress)
	return obj, err
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
	STIXCyberObservableObject
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
func NewEmailMessage(multipart bool, opts ...STIXOption) (*EmailMessage, error) {
	base := newSTIXCyberObservableObject(TypeEmailMessage)
	obj := &EmailMessage{
		STIXCyberObservableObject: base,
		IsMultipart:               multipart,
	}

	err := applyOptions(obj, opts)
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
	return obj, err
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
