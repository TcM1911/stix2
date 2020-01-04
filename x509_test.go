// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestX509Certificate(t *testing.T) {
	assert := assert.New(t)

	testStr := "test string"
	hashes := Hashes{SHA1: "0f01ed56a1e32a05e5ef96e4d779f34784af9a96"}
	ts := &Timestamp{time.Now()}
	v3 := X509v3Extension{SubjectAltName: "alt name"}
	num := int64(42)

	t.Run("missing_property", func(t *testing.T) {
		obj, err := NewX509Certificate()
		assert.Nil(obj)
		assert.Equal(ErrPropertyMissing, err)
	})

	t.Run("with_property", func(t *testing.T) {
		obj, err := NewX509Certificate(nil)
		assert.NotNil(obj)
		assert.NoError(err)
	})

	t.Run("payload_with_options", func(t *testing.T) {
		marking := &GranularMarking{}
		objmark := []Identifier{Identifier("id")}
		specVer := "2.0"

		opts := []X509CertificateOption{
			X509CertificateOptionGranularMarking(marking),
			X509CertificateOptionObjectMarking(objmark),
			X509CertificateOptionSpecVersion(specVer),
			X509CertificateOptionDefanged(true),
			X509CertificateOptionExtension("test", struct{}{}),
			//
			X509CertificateOptionSelfSigned(true),
			X509CertificateOptionHashes(hashes),
			X509CertificateOptionSerialNumber(testStr),
			X509CertificateOptionVersion(testStr),
			X509CertificateOptionSignatureAlgorithm(testStr),
			X509CertificateOptionIssuer(testStr),
			X509CertificateOptionValidityNotBefore(ts),
			X509CertificateOptionValidityNotAfter(ts),
			X509CertificateOptionSubject(testStr),
			X509CertificateOptionSubjectPublicKeyAlgorithm(testStr),
			X509CertificateOptionSubjectPublicKeyModulus(testStr),
			X509CertificateOptionSubjectPublicKeyExponent(num),
			X509CertificateOptionV3Extensions(v3),
		}
		obj, err := NewX509Certificate(opts...)
		assert.NotNil(obj)
		assert.NoError(err)
		assert.Equal(marking, obj.GranularMarking)
		assert.Equal(objmark, obj.ObjectMarking)
		assert.Equal(specVer, obj.SpecVersion)
		assert.True(obj.Defanged)

		assert.True(obj.SelfSigned)
		assert.Equal(testStr, obj.SerialNumber)
		assert.Equal(hashes, obj.Hashes)
		assert.Equal(testStr, obj.Version)
		assert.Equal(testStr, obj.SignatureAlgorithm)
		assert.Equal(testStr, obj.Issuer)
		assert.Equal(ts, obj.ValidityNotBefore)
		assert.Equal(ts, obj.ValidityNotAfter)
		assert.Equal(testStr, obj.Subject)
		assert.Equal(testStr, obj.SubjectPublicKeyAlghorithm)
		assert.Equal(testStr, obj.SubjectPublicKeyModulus)
		assert.Equal(num, obj.SubjectPublicKeyExponent)
		assert.Equal(v3, obj.X509v3Extensions)
	})

	t.Run("id-generation", func(t *testing.T) {
		tests := []struct {
			serial string
			hashes Hashes
			id     string
		}{
			{
				testStr,
				nil,
				"x509-certificate--95c4c7a8-d804-505a-be56-e48cf0907412",
			},
			{
				testStr,
				hashes,
				"x509-certificate--72619740-49d8-56c5-a082-639ff2c8f0a6",
			},
		}
		for _, test := range tests {
			opts := make([]X509CertificateOption, 0, 3)
			if test.serial != "" {
				opts = append(opts, X509CertificateOptionSerialNumber(test.serial))
			}
			if test.hashes != nil {
				opts = append(opts, X509CertificateOptionHashes(test.hashes))
			}
			obj, err := NewX509Certificate(opts...)
			assert.NoError(err)
			assert.Equal(Identifier(test.id), obj.ID)
		}
	})

	t.Run("parse_json", func(t *testing.T) {
		data := []byte(`
	{
  "type":"x509-certificate",
  "spec_version": "2.1",
  "id": "x509-certificate--b595eaf0-0b28-5dad-9e8e-0fab9c1facc9",
  "issuer":"C=ZA, ST=Western Cape, L=Cape Town, O=Thawte Consulting cc, OU=Certification Services Division, CN=Thawte Server CA/emailAddress=server-certs@thawte.com",
  "validity_not_before":"2016-03-12T12:00:00Z",
  "validity_not_after":"2016-08-21T12:00:00Z",
  "subject":"C=US, ST=Maryland, L=Pasadena, O=Brent Baccala, OU=FreeSoft, CN=www.freesoft.org/emailAddress=baccala@freesoft.org",
  "serial_number": "02:08:87:83:f2:13:58:1f:79:52:1e:66:90:0a:02:24:c9:6b:c7:dc",
  "x509_v3_extensions":{
    "basic_constraints":"critical,CA:TRUE, pathlen:0",
    "name_constraints":"permitted;IP:192.168.0.0/255.255.0.0",
    "policy_contraints":"requireExplicitPolicy:3",
    "key_usage":"critical, keyCertSign",
    "extended_key_usage":"critical,codeSigning,1.2.3.4",
    "subject_key_identifier":"hash",
    "authority_key_identifier":"keyid,issuer",
    "subject_alternative_name":"email:my@other.address,RID:1.2.3.4",
    "issuer_alternative_name":"issuer:copy",
    "crl_distribution_points":"URI:http://myhost.com/myca.crl",
    "inhibit_any_policy":"2",
    "private_key_usage_period_not_before":"2016-03-12T12:00:00Z",
    "private_key_usage_period_not_after":"2018-03-12T12:00:00Z",
    "certificate_policies":"1.2.4.5, 1.1.3.4"
  }
	}
	`)
		var obj *X509Certificate
		err := json.Unmarshal(data, &obj)
		assert.NoError(err)
		assert.Equal(Identifier("x509-certificate--b595eaf0-0b28-5dad-9e8e-0fab9c1facc9"), obj.ID)
		assert.Equal("2.1", obj.SpecVersion)
		assert.Equal(TypeX509Certificate, obj.Type)
		assert.Equal("C=ZA, ST=Western Cape, L=Cape Town, O=Thawte Consulting cc, OU=Certification Services Division, CN=Thawte Server CA/emailAddress=server-certs@thawte.com", obj.Issuer)
		assert.Equal("C=US, ST=Maryland, L=Pasadena, O=Brent Baccala, OU=FreeSoft, CN=www.freesoft.org/emailAddress=baccala@freesoft.org", obj.Subject)
		assert.Equal("02:08:87:83:f2:13:58:1f:79:52:1e:66:90:0a:02:24:c9:6b:c7:dc", obj.SerialNumber)
		assert.NotNil(obj.X509v3Extensions)
		assert.Equal("critical,CA:TRUE, pathlen:0", obj.X509v3Extensions.BasicConstraints)
		assert.Equal("critical,codeSigning,1.2.3.4", obj.X509v3Extensions.ExtendedKeyUsage)
		assert.Equal("email:my@other.address,RID:1.2.3.4", obj.X509v3Extensions.SubjectAltName)
	})
}
