// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import (
	"fmt"
	"strings"
)

// X509Certificate object represents the properties of an X.509 certificate,
// as defined by ITU recommendation X.509 [X.509]. An X.509 Certificate object
// MUST contain at least one object specific property (other than type) from
// this object.
type X509Certificate struct {
	STIXCyberObservableObject
	// SelfSigned specifies whether the certificate is self-signed, i.e.,
	// whether it is signed by the same entity whose identity it certifies.
	SelfSigned bool `json:"is_self_signed,omitempty"`
	// Hashes specifies any hashes that were calculated for the entire contents
	// of the certificate.
	Hashes Hashes `json:"hashes,omitempty"`
	// Version specifies the version of the encoded certificate.
	Version string `json:"version,omitempty"`
	// SerialNumber specifies the unique identifier for the certificate, as
	// issued by a specific Certificate Authority.
	SerialNumber string `json:"serial_number,omitempty"`
	// SignatureAlgorithm specifies the name of the algorithm used to sign the
	// certificate.
	SignatureAlgorithm string `json:"signature_algorithm,omitempty"`
	// Issuer specifies the name of the Certificate Authority that issued the
	// certificate.
	Issuer string `json:"issuer,omitempty"`
	// ValidityNotBefore specifies the date on which the certificate validity
	// period begins.
	ValidityNotBefore *Timestamp `json:"validity_not_before,omitempty"`
	// ValidityNotAfter specifies the date on which the certificate validity
	// period ends.
	ValidityNotAfter *Timestamp `json:"validity_not_after,omitempty"`
	// Subject specifies the name of the entity associated with the public key
	// stored in the subject public key field of the certificate.
	Subject string `json:"subject,omitempty"`
	// SubjectPublicKeyAlghorithm specifies the name of the algorithm with
	// which to encrypt data being sent to the subject.
	SubjectPublicKeyAlghorithm string `json:"subject_public_key_algorithm,omitempty"`
	// SubjectPublicKeyModulus specifies the modulus portion of the subject’s
	// public RSA key.
	SubjectPublicKeyModulus string `json:"subject_public_key_modulus,omitempty"`
	// SubjectPublicKeyExponent specifies the exponent portion of the subject’s
	// public RSA key, as an integer.
	SubjectPublicKeyExponent int64 `json:"subject_public_key_exponent,omitempty"`
	// X509v3Extensions specifies any standard X.509 v3 extensions that may be
	// used in the certificate.
	X509v3Extensions X509v3Extension `json:"x509_v3_extensions,omitempty"`
}

// NewX509Certificate creates a new X509Certificate object.
func NewX509Certificate(opts ...X509CertificateOption) (*X509Certificate, error) {
	if len(opts) == 0 {
		return nil, ErrPropertyMissing
	}
	base := newSTIXCyberObservableObject(TypeX509Certificate)
	obj := &X509Certificate{
		STIXCyberObservableObject: base,
	}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(obj)
	}

	idContri := make([]string, 0, 2)
	if len(obj.Hashes) != 0 {
		idContri = append(idContri, fmt.Sprintf(`%s`, obj.Hashes.getIDContribution()))
	}
	if obj.SerialNumber != "" {
		idContri = append(idContri, fmt.Sprintf(`"%s"`, obj.SerialNumber))
	}
	obj.ID = NewObservableIdenfier(fmt.Sprintf("[%s]", strings.Join(idContri, ",")), TypeX509Certificate)
	return obj, nil
}

// X509CertificateOption is an optional parameter when constructing a
// X509Certificate object.
type X509CertificateOption func(a *X509Certificate)

/*
	Base object options
*/

// X509CertificateOptionSpecVersion sets the STIX spec version.
func X509CertificateOptionSpecVersion(ver string) X509CertificateOption {
	return func(obj *X509Certificate) {
		obj.SpecVersion = ver
	}
}

// X509CertificateOptionObjectMarking sets the object marking attribute.
func X509CertificateOptionObjectMarking(om []Identifier) X509CertificateOption {
	return func(obj *X509Certificate) {
		obj.ObjectMarking = om
	}
}

// X509CertificateOptionGranularMarking sets the granular marking attribute.
func X509CertificateOptionGranularMarking(gm *GranularMarking) X509CertificateOption {
	return func(obj *X509Certificate) {
		obj.GranularMarking = gm
	}
}

// X509CertificateOptionDefanged sets the defanged attribute.
func X509CertificateOptionDefanged(b bool) X509CertificateOption {
	return func(obj *X509Certificate) {
		obj.Defanged = b
	}
}

// X509CertificateOptionExtension adds an extension.
func X509CertificateOptionExtension(name string, value interface{}) X509CertificateOption {
	return func(obj *X509Certificate) {
		// Ignoring the error.
		obj.addExtension(name, value)
	}
}

/*
	X509Certificate object options
*/

// X509CertificateOptionSelfSigned sets the self-signed attribute.
func X509CertificateOptionSelfSigned(s bool) X509CertificateOption {
	return func(obj *X509Certificate) {
		obj.SelfSigned = s
	}
}

// X509CertificateOptionHashes sets the hashes attribute.
func X509CertificateOptionHashes(s Hashes) X509CertificateOption {
	return func(obj *X509Certificate) {
		obj.Hashes = s
	}
}

// X509CertificateOptionVersion sets the version attribute.
func X509CertificateOptionVersion(s string) X509CertificateOption {
	return func(obj *X509Certificate) {
		obj.Version = s
	}
}

// X509CertificateOptionSerialNumber sets the serial number attribute.
func X509CertificateOptionSerialNumber(s string) X509CertificateOption {
	return func(obj *X509Certificate) {
		obj.SerialNumber = s
	}
}

// X509CertificateOptionSignatureAlgorithm sets the signature algorithm attribute.
func X509CertificateOptionSignatureAlgorithm(s string) X509CertificateOption {
	return func(obj *X509Certificate) {
		obj.SignatureAlgorithm = s
	}
}

// X509CertificateOptionIssuer sets the issuer attribute.
func X509CertificateOptionIssuer(s string) X509CertificateOption {
	return func(obj *X509Certificate) {
		obj.Issuer = s
	}
}

// X509CertificateOptionValidityNotBefore sets the validity not before
// attribute.
func X509CertificateOptionValidityNotBefore(s *Timestamp) X509CertificateOption {
	return func(obj *X509Certificate) {
		obj.ValidityNotBefore = s
	}
}

// X509CertificateOptionValidityNotAfter sets the validity not after
// attribute.
func X509CertificateOptionValidityNotAfter(s *Timestamp) X509CertificateOption {
	return func(obj *X509Certificate) {
		obj.ValidityNotAfter = s
	}
}

// X509CertificateOptionSubject sets the subject attribute.
func X509CertificateOptionSubject(s string) X509CertificateOption {
	return func(obj *X509Certificate) {
		obj.Subject = s
	}
}

// X509CertificateOptionSubjectPublicKeyAlgorithm sets the subject public key
// algorithm attribute.
func X509CertificateOptionSubjectPublicKeyAlgorithm(s string) X509CertificateOption {
	return func(obj *X509Certificate) {
		obj.SubjectPublicKeyAlghorithm = s
	}
}

// X509CertificateOptionSubjectPublicKeyModulus sets the subject public key
// modulus attribute.
func X509CertificateOptionSubjectPublicKeyModulus(s string) X509CertificateOption {
	return func(obj *X509Certificate) {
		obj.SubjectPublicKeyModulus = s
	}
}

// X509CertificateOptionSubjectPublicKeyExponent sets the subject public key
// exponent attribute.
func X509CertificateOptionSubjectPublicKeyExponent(s int64) X509CertificateOption {
	return func(obj *X509Certificate) {
		obj.SubjectPublicKeyExponent = s
	}
}

// X509CertificateOptionV3Extensions sets the x.509v3 extensions attribute.
func X509CertificateOptionV3Extensions(s X509v3Extension) X509CertificateOption {
	return func(obj *X509Certificate) {
		obj.X509v3Extensions = s
	}
}

// X509v3Extension captures properties associated with X.509 v3 extensions,
// which serve as a mechanism for specifying additional information such as
// alternative subject names. An object using the X.509 v3 Extensions type MUST
// contain at least one property from this type.
type X509v3Extension struct {
	// BasicConstraints specifies a multi-valued extension which indicates
	// whether a certificate is a CA certificate. The first (mandatory) name is
	// CA followed by TRUE or FALSE. If CA is TRUE, then an optional pathlen
	// name followed by a non-negative value can be included. Also equivalent
	// to the object ID (OID) value of 2.5.29.19.
	BasicConstraints string `json:"basic_constraints,omitempty"`
	// NameConstraints specifies a namespace within which all subject names in
	// subsequent certificates in a certification path MUST be located. Also
	// equivalent to the object ID (OID) value of 2.5.29.30.
	NameConstraints string `json:"name_constraints,omitempty"`
	// PolicyConstraints specifies any constraints on path validation for
	// certificates issued to CAs. Also equivalent to the object ID (OID) value
	// of 2.5.29.36.
	PolicyConstraints string `json:"policy_constraints,omitempty"`
	// KeyUsage specifies a multi-valued extension consisting of a list of
	// names of the permitted key usages. Also equivalent to the object ID
	// (OID) value of 2.5.29.15.
	KeyUsage string `json:"key_usage,omitempty"`
	// ExtendedKeyUsage specifies a list of usages indicating purposes for
	// which the certificate public key can be used for. Also equivalent to the
	// object ID (OID) value of 2.5.29.37.
	ExtendedKeyUsage string `json:"extended_key_usage,omitempty"`
	// SubjectKeyIdentifier specifies the identifier that provides a means of
	// identifying certificates that contain a particular public key. Also
	// equivalent to the object ID (OID) value of 2.5.29.14.
	SubjectKeyIdentifier string `json:"subject_key_identifier,omitempty"`
	// AuthorityKeyIdentifier specifies the identifier that provides a means of
	// identifying the public key corresponding to the private key used to sign
	// a certificate. Also equivalent to the object ID (OID) value of
	// 2.5.29.35.
	AuthorityKeyIdentifier string `json:"authority_key_identifier,omitempty"`
	// SubjectAltName specifies the additional identities to be bound to the
	// subject of the certificate. Also equivalent to the object ID (OID) value
	// of 2.5.29.17.
	SubjectAltName string `json:"subject_alternative_name,omitempty"`
	// IssuerAltName specifies the additional identities to be bound to the
	// issuer of the certificate. Also equivalent to the object ID (OID) value
	// of 2.5.29.18.
	IssuerAltName string `json:"issuer_alternative_name,omitempty"`
	// SubjectDirectoryAttributes specifies the identification attributes
	// (e.g., nationality) of the subject. Also equivalent to the object ID
	// (OID) value of 2.5.29.9.
	SubjectDirectoryAttributes string `json:"subject_directory_attributes,omitempty"`
	// CRLDistributionPoints specifies how CRL information is obtained. Also
	// equivalent to the object ID (OID) value of 2.5.29.31.
	CRLDistributionPoints string `json:"crl_distribution_points,omitempty"`
	// InhibitAnyPolicy specifies the number of additional certificates that
	// may appear in the path before anyPolicy is no longer permitted. Also
	// equivalent to the object ID (OID) value of 2.5.29.54.
	InhibitAnyPolicy string `json:"inhibit_any_policy,omitempty"`
	// PrivateKeyUsagePeriodNotBefore specifies the date on which the validity
	// period begins for the private key, if it is different from the validity
	// period of the certificate.
	PrivateKeyUsagePeriodNotBefore *Timestamp `json:"private_key_usage_period_not_before,omitempty"`
	// PrivateKeyUsagePeriodNotAfter specifies the date on which the validity
	// period ends for the private key, if it is different from the validity
	// period of the certificate.
	PrivateKeyUsagePeriodNotAfter *Timestamp `json:"private_key_usage_period_not_after,omitempty"`
	// CertificatePolicies specifies a sequence of one or more policy
	// information terms, each of which consists of an object identifier (OID)
	// and optional qualifiers. Also equivalent to the object ID (OID) value of
	// 2.5.29.32.
	CertificatePolicies string `json:"certificate_policies,omitempty"`
	// PolicyMappings specifies one or more pairs of OIDs; each pair includes
	// an issuerDomainPolicy and a subjectDomainPolicy. The pairing indicates
	// whether the issuing CA considers its issuerDomainPolicy equivalent to
	// the subject CA's subjectDomainPolicy. Also equivalent to the object ID
	// (OID) value of 2.5.29.33.
	PolicyMappings string `json:"policy_mappings,omitempty"`
}
