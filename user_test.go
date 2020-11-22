// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestUserAccount(t *testing.T) {
	assert := assert.New(t)

	testStr := "test string"
	ts := &Timestamp{time.Now()}

	t.Run("missing_property", func(t *testing.T) {
		obj, err := NewUserAccount()
		assert.Nil(obj)
		assert.Equal(ErrPropertyMissing, err)
	})

	t.Run("with_property", func(t *testing.T) {
		obj, err := NewUserAccount(nil)
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
			OptionExtension("test", struct{}{}),
			//
			OptionUserID(testStr),
			OptionCredential(testStr),
			OptionAccountLogin(testStr),
			OptionAccountType(AccountWindowsLocal),
			OptionDisplayName(testStr),
			OptionIsServiceAccount(true),
			OptionIsPrivileged(true),
			OptionCanEscalatePrivs(true),
			OptionIsDisabled(true),
			OptionAccountCreated(ts),
			OptionAccountExpires(ts),
			OptionCredentialLastChanged(ts),
			OptionAccountFirstLogin(ts),
			OptionAccountLastLogin(ts),
		}
		obj, err := NewUserAccount(opts...)
		assert.NotNil(obj)
		assert.NoError(err)
		assert.Equal(marking, obj.GranularMarking)
		assert.Equal(objmark, obj.ObjectMarking)
		assert.Equal(specVer, obj.SpecVersion)
		assert.True(obj.Defanged)

		assert.Equal(testStr, obj.UserID)
		assert.Equal(testStr, obj.Credential)
		assert.Equal(testStr, obj.AccountLogin)
		assert.Equal(AccountWindowsLocal, obj.AccountType)
		assert.Equal(testStr, obj.DisplayName)
		assert.True(obj.IsServiceAccount)
		assert.True(obj.IsPrivileged)
		assert.True(obj.CanEscalatePrivs)
		assert.True(obj.IsDisabled)
		assert.Equal(ts, obj.AccountCreated)
		assert.Equal(ts, obj.AccountExpires)
		assert.Equal(ts, obj.CredentialLastChanged)
		assert.Equal(ts, obj.AccountFirstLogin)
		assert.Equal(ts, obj.AccountLastLogin)
	})

	t.Run("id-generation", func(t *testing.T) {
		tests := []struct {
			typ   string
			uid   string
			login string
			id    string
		}{
			{
				AccountUnix,
				"",
				"",
				"user-account--5e8f515f-35db-5c9b-b413-65cc81740e1b",
			},
			{
				AccountUnix,
				"1001",
				"",
				"user-account--d7498183-59da-5cbd-98a3-d9c95ea4276c",
			},
			{
				AccountUnix,
				"1001",
				"jdoe",
				"user-account--ac9fed0c-94ad-5651-8630-7ac1f6ea0c67",
			},
		}
		for _, test := range tests {
			opts := make([]STIXOption, 0, 3)
			if test.uid != "" {
				opts = append(opts, OptionUserID(test.uid))
			}
			if test.typ != "" {
				opts = append(opts, OptionAccountType(test.typ))
			}
			if test.login != "" {
				opts = append(opts, OptionAccountLogin(test.login))
			}
			obj, err := NewUserAccount(opts...)
			assert.NoError(err)
			assert.Equal(Identifier(test.id), obj.ID)
		}
	})

	t.Run("unix-extension", func(t *testing.T) {
		ext := &UNIXAccountExtension{GID: int64(1)}
		f, _ := NewUserAccount(OptionExtension(ExtUnixAccount, ext))
		assert.Len(f.Extensions, 1)
		stored := f.UNIXAccountExtension()
		assert.Equal(ext, stored)
	})

	t.Run("unix-extension-nil", func(t *testing.T) {
		f, _ := NewUserAccount(nil)
		assert.Len(f.Extensions, 0)
		stored := f.UNIXAccountExtension()
		assert.Nil(stored)
	})

	t.Run("parse_json", func(t *testing.T) {
		data := []byte(`
{
  "type": "user-account",
  "spec_version": "2.1",
  "id": "user-account--9bd3afcf-deee-54f9-83e2-520653cb6bba",
  "user_id": "thegrugq_ebooks",
  "account_login": "thegrugq_ebooks",
  "account_type": "twitter",
  "display_name": "the grugq"
}`)
		var obj *UserAccount
		err := json.Unmarshal(data, &obj)
		assert.NoError(err)
		assert.Equal(Identifier("user-account--9bd3afcf-deee-54f9-83e2-520653cb6bba"), obj.ID)
		assert.Equal("2.1", obj.SpecVersion)
		assert.Equal(TypeUserAccount, obj.Type)
		assert.Equal("thegrugq_ebooks", obj.UserID)
		assert.Equal("thegrugq_ebooks", obj.AccountLogin)
		assert.Equal("the grugq", obj.DisplayName)
		assert.Equal(AccountTwitter, obj.AccountType)
	})
}
