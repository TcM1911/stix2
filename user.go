// Copyright 2020 Joakim Kennedy. All rights reserved. Use of
// this source code is governed by the included BSD license.

package stix2

import (
	"encoding/json"
	"fmt"
	"strings"
)

// UserAccount object represents an instance of any type of user account,
// including but not limited to operating system, device, messaging service,
// and social media platform accounts. As all properties of this object are
// optional, at least one of the properties defined below MUST be included when
// using this object.
type UserAccount struct {
	STIXCyberObservableObject
	// UserID specifies the identifier of the account. The format of the
	// identifier depends on the system the user account is maintained in, and
	// may be a numeric ID, a GUID, an account name, an email address, etc. The
	// UserID property should be populated with whatever field is the unique
	// identifier for the system the account is a member of. For example, on
	// UNIX systems it would be populated with the UID.
	UserID string `json:"user_id,omitempty"`
	// Credential specifies a cleartext credential. This is only intended to be
	// used in capturing metadata from malware analysis (e.g., a hard-coded
	// domain administrator password that the malware attempts to use for
	// lateral movement) and SHOULD NOT be used for sharing of PII.
	Credential string `json:"credential,omitempty"`
	// AccountLogin specifies the account login string, used in cases where the
	// UserID property specifies something other than what a user would type
	// when they login.
	//
	// For example, in the case of a Unix account with UserID 0, the account_login
	// might be “root”.
	AccountLogin string `json:"account_login,omitempty"`
	// AccountType specifies the type of the account.
	AccountType string `json:"account_type,omitempty"`
	// DisplayName specifies the display name of the account, to be shown in
	// user interfaces, if applicable.
	DisplayName string `json:"display_name,omitempty"`
	// IsServiceAccount indicates that the account is associated with a network
	// service or system process (daemon), not a specific individual.
	IsServiceAccount bool `json:"is_service_account,omitempty"`
	// IsPrivileged specifies that the account has elevated privileges (i.e.,
	// in the case of root on Unix or the Windows Administrator account).
	IsPrivileged bool `json:"is_privileged,omitempty"`
	// CanEscalatePrivs specifies that the account has the ability to escalate
	// privileges (i.e., in the case of sudo on Unix or a Windows Domain Admin
	// account)
	CanEscalatePrivs bool `json:"can_escalate_privs,omitempty"`
	// IsDisabled specifies if the account is disabled.
	IsDisabled bool `json:"is_disabled,omitempty"`
	// AccountCreated specifies when the account was created.
	AccountCreated *Timestamp `json:"account_created,omitempty"`
	// AccountExpires specifies the expiration date of the account.
	AccountExpires *Timestamp `json:"account_expires,omitempty"`
	// CredentialLastChanged specifies when the account credential was last
	// changed.
	CredentialLastChanged *Timestamp `json:"credential_last_changed,omitempty"`
	// AccountFirstLogin specifies when the account was first accessed.
	AccountFirstLogin *Timestamp `json:"account_first_login,omitempty"`
	// AccountLastLogin specifies when the account was last accessed.
	AccountLastLogin *Timestamp `json:"account_last_login,omitempty"`
}

// UNIXAccountExtension returns the Unix account extension for the object or
// nil.
func (n *UserAccount) UNIXAccountExtension() *UNIXAccountExtension {
	data, ok := n.Extensions[ExtUnixAccount]
	if !ok {
		return nil
	}
	var v UNIXAccountExtension
	json.Unmarshal(data, &v)
	return &v
}

// NewUserAccount creates a new UserAccount object.
func NewUserAccount(opts ...STIXOption) (*UserAccount, error) {
	if len(opts) == 0 {
		return nil, ErrPropertyMissing
	}
	base := newSTIXCyberObservableObject(TypeUserAccount)
	obj := &UserAccount{
		STIXCyberObservableObject: base,
	}

	err := applyOptions(obj, opts)

	idContri := make([]string, 0, 3)
	if obj.AccountType != "" {
		idContri = append(idContri, fmt.Sprintf(`"%s"`, obj.AccountType))
	}
	if obj.UserID != "" {
		idContri = append(idContri, fmt.Sprintf(`"%s"`, obj.UserID))
	}
	if obj.AccountLogin != "" {
		idContri = append(idContri, fmt.Sprintf(`"%s"`, obj.AccountLogin))
	}
	obj.ID = NewObservableIdenfier(fmt.Sprintf("[%s]", strings.Join(idContri, ",")), TypeUserAccount)
	return obj, err
}

const (
	// AccountFacebook specifies a Facebook account.
	AccountFacebook string = "facebook"
	// AccountLdap specifies an LDAP account.
	AccountLdap string = "ldap"
	// AccountNis specifies a NIS account
	AccountNis string = "nis"
	// AccountOpenid specifies an OpenID account.
	AccountOpenid string = "openid"
	// AccountRadius specifies a RADIUS account.
	AccountRadius string = "radius"
	// AccountSkype specifies a Skype account.
	AccountSkype string = "skype"
	// AccountTacacs specifies a TACACS account.
	AccountTacacs string = "tacacs"
	// AccountTwitter specifies a Twitter account.
	AccountTwitter string = "twitter"
	// AccountUnix specifies a POSIX account.
	AccountUnix string = "unix"
	// AccountWindowsLocal specifies a Windows local account.
	AccountWindowsLocal string = "windows-local"
	// AccountWindowsDomain specifies a Windows domain account.
	AccountWindowsDomain string = "windows-domain"
)

// UNIXAccountExtension specifies a default extension for capturing the
// additional information for an account on a UNIX system.
type UNIXAccountExtension struct {
	// GID specifies the primary group ID of the account.
	GID int64 `json:"gid,omitempty"`
	// Groups specifies a list of names of groups that the account is a member
	// of.
	Groups []string `json:"groups,omitempty"`
	// Home specifies the home directory of the account.
	Home string `json:"home_dir,omitempty"`
	// Shell specifies the account’s command shell.
	Shell string `json:"shell,omitempty"`
}
