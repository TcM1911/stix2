// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewExternalReference(t *testing.T) {
	assert := assert.New(t)
	tests := []struct {
		Name       string
		Desc       string
		URL        string
		ExternalID string
	}{
		{"Test1", "Description", "", ""},
		{"Test2", "", "http://example.com", ""},
		{"Test3", "", "", "1234"},
	}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			expected := &ExternalReference{Name: test.Name, Description: test.Desc, URL: test.URL, ExternalID: test.ExternalID}
			actual, err := NewExternalReference(test.Name, test.Desc, test.URL, test.ExternalID, nil)
			assert.NoError(err)
			assert.Equal(expected, actual)
		})
	}

	errtests := []struct {
		Name       string
		Desc       string
		URL        string
		ExternalID string
		Err        error
	}{
		{"", "Description", "", "", ErrPropertyMissing},
		{"Test2", "", "", "", ErrPropertyMissing},
	}
	for _, test := range errtests {
		t.Run(test.Name, func(t *testing.T) {
			val, err := NewExternalReference(test.Name, test.Desc, test.URL, test.ExternalID, nil)
			assert.Equal(test.Err, err)
			assert.Nil(val)
		})
	}
}

func TestParseExternalReference(t *testing.T) {
	assert := assert.New(t)
	tests := []struct {
		Name     string
		JSON     []byte
		Expected *ExternalReference
	}{
		{"Veris", externalRefVeris, &ExternalReference{
			Name:       "veris",
			ExternalID: "0001AA7F-C601-424A-B2B8-BE6C9F5164E7",
			URL:        "https://github.com/vz-risk/VCDB/blob/125307638178efddd3ecfe2c267ea434667a4eea/data/json/validated/0001AA7F-C601-424A-B2B8-BE6C9F5164E7.json",
			Hashes:     map[HashAlgorithm]string{SHA256: "6db12788c37247f2316052e142f42f4b259d6561751e5f401a1ae2a6df9c674b"},
		}},
		{"CAPEC", externalRefCAPEC, &ExternalReference{
			Name:       "capec",
			ExternalID: "CAPEC-550",
			URL:        "http://capec.mitre.org/data/definitions/550.html",
		}},
		{"ACME", externalRefACME, &ExternalReference{
			Name:        "ACME Threat Intel",
			Description: "Threat report",
			URL:         "http://www.example.com/threat-report.pdf",
		}},
		{"Bugzilla", externalRefBugzilla, &ExternalReference{
			Name:       "ACME Bugzilla",
			ExternalID: "1370",
			URL:        "https://www.example.com/bugs/1370",
		}},
		{"ThreatIntel", externalRefThreatIntel, &ExternalReference{
			Name:        "ACME Threat Intel",
			Description: "Threat report",
		}},
	}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			actual, err := ParseExternalReference(test.JSON)
			assert.NoError(err)
			assert.Equal(test.Expected, actual)
		})
	}
}

var externalRefVeris = []byte(`{
  "source_name": "veris",
  "external_id": "0001AA7F-C601-424A-B2B8-BE6C9F5164E7",
  "url":
  "https://github.com/vz-risk/VCDB/blob/125307638178efddd3ecfe2c267ea434667a4eea/data/json/validated/0001AA7F-C601-424A-B2B8-BE6C9F5164E7.json",
  "hashes": {
	"SHA-256":
	"6db12788c37247f2316052e142f42f4b259d6561751e5f401a1ae2a6df9c674b"
  }
}`)

var externalRefCAPEC = []byte(`{
  "source_name": "capec",
  "external_id": "CAPEC-550",
  "url": "http://capec.mitre.org/data/definitions/550.html"
}`)

var externalRefACME = []byte(`{
  "source_name": "ACME Threat Intel",
  "description": "Threat report",
  "url": "http://www.example.com/threat-report.pdf"
}`)

var externalRefBugzilla = []byte(`{
  "source_name": "ACME Bugzilla",
  "external_id": "1370",
  "url": "https://www.example.com/bugs/1370"
}`)

var externalRefThreatIntel = []byte(`{
  "source_name": "ACME Threat Intel",
  "description": "Threat report"
}`)

func TestHashes(t *testing.T) {
	assert := assert.New(t)
	data := []byte(`{
  "SHA-256": "6db12788c37247f2316052e142f42f4b259d6561751e5f401a1ae2a6df9c674b",
  "x_foo_hash": "aaaabbbbccccddddeeeeffff0123457890"
}`)
	var hashes Hashes
	err := json.Unmarshal(data, &hashes)
	assert.NoError(err)
	assert.Len(hashes, 2)

	sha, SHAExist := hashes[SHA256]
	foo, fooExist := hashes[HashAlgorithm("x_foo_hash")]
	assert.True(SHAExist)
	assert.True(fooExist)
	assert.Equal("6db12788c37247f2316052e142f42f4b259d6561751e5f401a1ae2a6df9c674b", sha)
	assert.Equal("aaaabbbbccccddddeeeeffff0123457890", foo)
}

func TestIdentifier(t *testing.T) {
	assert := assert.New(t)
	t.Run("IsValidCheck", func(t *testing.T) {
		valid := IsValidIdentifier(Identifier("indicator--e2e1a340-4415-4ba8-9671-f7343fbf0836"))
		invalid := IsValidIdentifier(Identifier("notvalid--foo"))
		invalidLen := IsValidIdentifier(Identifier("notvalidfoo"))
		assert.True(valid)
		assert.False(invalid)
		assert.False(invalidLen)
	})

	t.Run("NewRandomID", func(t *testing.T) {
		id := NewIdentifier(TypeIndicator)
		assert.True(IsValidIdentifier(id))
		assert.Contains(id, "indicator--")
	})

	t.Run("NewObservableID", func(t *testing.T) {
		id := NewObservableIdenfier("198.51.100.3", TypeIPv4Addr)
		assert.Equal(Identifier("ipv4-addr--0ec1740c-3e52-5d42-8659-da680987dff8"), id)
	})
}

func TestKillChainPhase(t *testing.T) {
	assert := assert.New(t)

	t.Run("missing_properties", func(t *testing.T) {
		o, err := NewKillChainPhase(LockheedMartinCyberKillChain, "")
		assert.Error(err)
		assert.Nil(o)
		o, err = NewKillChainPhase("", "foo")
		assert.Error(err)
		assert.Nil(o)
	})
	t.Run("valid_lockheed", func(t *testing.T) {
		expected := &KillChainPhase{Name: LockheedMartinCyberKillChain, Phase: "reconnaissance"}
		o, err := NewKillChainPhase(LockheedMartinCyberKillChain, "reconnaissance")
		assert.NoError(err)
		assert.Equal(expected, o)
	})
	t.Run("lockheed", func(t *testing.T) {
		data := []byte(`{
      "kill_chain_name": "lockheed-martin-cyber-kill-chain",
      "phase_name": "reconnaissance"
    }`)
		expected := &KillChainPhase{Name: LockheedMartinCyberKillChain, Phase: "reconnaissance"}
		o, err := ParseKillChainPhase(data)
		assert.NoError(err)
		assert.Equal(expected, o)
	})
	t.Run("lockheed", func(t *testing.T) {
		data := []byte(`{
      "kill_chain_name": "lockheed-martin-cyber-kill-chain",
      "phase_name": "reconnaissance"
    }`)
		expected := &KillChainPhase{Name: LockheedMartinCyberKillChain, Phase: "reconnaissance"}
		o, err := ParseKillChainPhase(data)
		assert.NoError(err)
		assert.Equal(expected, o)
	})
	t.Run("foo", func(t *testing.T) {
		data := []byte(`{
      "kill_chain_name": "foo",
      "phase_name": "pre-attack"
    }`)
		expected := &KillChainPhase{Name: "foo", Phase: "pre-attack"}
		o, err := ParseKillChainPhase(data)
		assert.NoError(err)
		assert.Equal(expected, o)
	})
}

func TestTimestamp(t *testing.T) {
	assert := assert.New(t)
	t.Run("Unmarshal", func(t *testing.T) {
		var s struct{ Created *Timestamp }
		data := []byte(`{"created": "2016-01-20T12:31:12.123Z"}`)
		err := json.Unmarshal(data, &s)
		assert.NoError(err)
		assert.Equal(2016, s.Created.Year())
		assert.Equal(time.Month(1), s.Created.Month())
		assert.Equal(20, s.Created.Day())
		assert.Equal(12, s.Created.Hour())
		assert.Equal(31, s.Created.Minute())
		assert.Equal(12, s.Created.Second())
	})

	t.Run("Marshal", func(t *testing.T) {
		tm, err := time.Parse(time.RFC3339Nano, "2016-01-20T12:31:12.123Z")
		assert.NoError(err, "Error when creating expected timestamp")
		s := struct{ Created *Timestamp }{Created: &Timestamp{tm}}
		assert.Equal(2016, s.Created.Year())
		data, err := json.Marshal(&s)
		assert.NoError(err)
		assert.Contains(string(data), "2016-01-20T12:31:12.123Z")
	})

	t.Run("Unmarshal_no_sub", func(t *testing.T) {
		var s struct{ Created *Timestamp }
		data := []byte(`{"created": "2016-01-20T12:31:12Z"}`)
		err := json.Unmarshal(data, &s)
		assert.NoError(err)
		assert.Equal(2016, s.Created.Year())
		assert.Equal(time.Month(1), s.Created.Month())
		assert.Equal(20, s.Created.Day())
		assert.Equal(12, s.Created.Hour())
		assert.Equal(31, s.Created.Minute())
		assert.Equal(12, s.Created.Second())
	})

	t.Run("Marshal_no_sub", func(t *testing.T) {
		tm, err := time.Parse(time.RFC3339Nano, "2016-01-20T12:31:12Z")
		assert.NoError(err, "Error when creating expected timestamp")
		s := struct{ Created *Timestamp }{Created: &Timestamp{tm}}
		assert.Equal(2016, s.Created.Year())
		data, err := json.Marshal(&s)
		assert.NoError(err)
		assert.Contains(string(data), "2016-01-20T12:31:12.000Z")
	})
}

func TestBinaryEncoding(t *testing.T) {
	assert := assert.New(t)
	encodedData := "\"QmFzZTY0IGVuY29kZWQgZGF0YQ==\""
	rawdata := []byte("Base64 encoded data")

	t.Run("decoding", func(t *testing.T) {
		var actual Binary
		p := &actual
		p.UnmarshalJSON([]byte(encodedData))
		assert.Equal(rawdata, []byte(actual))
	})

	t.Run("encoding", func(t *testing.T) {
		data := Binary(rawdata)
		actual, err := data.MarshalJSON()
		assert.NoError(err)
		assert.Equal(encodedData, string(actual))
	})
}

func TestHashContributing(t *testing.T) {
	md5Hash := "0da609bd9ec46237557373f1c5cfcae9"
	md5 := `{"MD5":"0da609bd9ec46237557373f1c5cfcae9"}`
	shasum := "d29359a1ca7f874adb7443aa19abe4444171d940"
	sha := `{"SHA-1":"d29359a1ca7f874adb7443aa19abe4444171d940"}`
	sha256sum := "d29359a1ca7f874adb7443aa19abe4444171d940"
	sha256 := `{"SHA-256":"d29359a1ca7f874adb7443aa19abe4444171d940"}`
	sha512sum := "c6d15372dcdef9d7426fc12fdcf3ad2be3022faebb3ad17655da572abbc9f18b9b5078b271030b377a9f98005a729c08cb7d46719d268b9494028773a9a9302d"
	sha512 := `{"SHA-512":"c6d15372dcdef9d7426fc12fdcf3ad2be3022faebb3ad17655da572abbc9f18b9b5078b271030b377a9f98005a729c08cb7d46719d268b9494028773a9a9302d"}`

	tests := []struct {
		hashes   Hashes
		expected string
	}{
		{Hashes{"SHA-512": sha512sum}, sha512},
		{Hashes{"SHA-256": sha256sum}, sha256},
		{Hashes{"SHA-1": shasum}, sha},
		{Hashes{"MD5": md5Hash}, md5},
		{Hashes{"SHA-256": sha256sum, "SHA-1": shasum}, sha},
		{Hashes{}, ""},
	}

	for _, test := range tests {
		actual := test.hashes.getIDContribution()
		assert.Equal(t, test.expected, actual)
	}
}

func TestHasValidIdentifier(t *testing.T) {
	assert := assert.New(t)

	for _, v := range AllTypes {
		for i := 0; i < 100; i++ {
			id := NewIdentifier(v)
			obj := &STIXDomainObject{
				Type: v,
				ID:   id,
			}
			assert.True(HasValidIdentifier(obj))
		}
	}
}
