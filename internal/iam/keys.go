package iam

import (
	"crypto/md5"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
)

const maxKeysPerUser = 2

// keyOwner resolves the user an access-key operation is about. Without a
// UserName it is the caller; a root caller then acts on the named key
// wherever it lives in the account.
func (c *call) keyOwner() (string, error) {
	if name := c.f.str("UserName"); name != "" {
		u, err := c.user(name)
		if err != nil {
			return "", err
		}
		return u.Name, nil
	}
	if c.who.Kind == "user" {
		return c.who.UserName, nil
	}
	if id := c.f.str("AccessKeyId"); id != "" {
		var owner string
		err := c.tx.QueryRowContext(c.ctx, `SELECT user_name FROM access_keys WHERE account_id=? AND kind='user' AND access_key=?`, c.account, id).Scan(&owner)
		if err == nil {
			return owner, nil
		}
	}
	return "", noSuchEntity("The user with name %s cannot be found.", c.who.UserName)
}

func createAccessKey(c *call) (obj, error) {
	owner, err := c.keyOwner()
	if err != nil {
		return nil, err
	}
	var n int
	if err := c.tx.QueryRowContext(c.ctx, `SELECT COUNT(*) FROM access_keys WHERE account_id=? AND kind='user' AND user_name=?`, c.account, owner).Scan(&n); err != nil {
		return nil, err
	}
	if n >= maxKeysPerUser {
		return nil, limitExceeded("Cannot exceed quota for AccessKeysPerUser: %d", maxKeysPerUser)
	}
	id, secret := randomID("AKIA", 16), randomSecret(40)
	if _, err := c.tx.ExecContext(c.ctx, `INSERT INTO access_keys(access_key, secret_key, account_id, user_name, status, created, kind) VALUES (?, ?, ?, ?, 'Active', ?, 'user')`,
		id, secret, c.account, owner, c.now.UnixMilli()); err != nil {
		return nil, err
	}
	return obj{{"AccessKey", obj{{"UserName", owner}, {"AccessKeyId", id}, {"Status", "Active"}, {"SecretAccessKey", secret}, {"CreateDate", c.now}}}}, nil
}

func listAccessKeys(c *call) (obj, error) {
	owner, err := c.keyOwner()
	if err != nil {
		return nil, err
	}
	rows, err := c.tx.QueryContext(c.ctx, `SELECT access_key, status, created FROM access_keys WHERE account_id=? AND kind='user' AND user_name=? ORDER BY created, rowid`, c.account, owner)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := members{}
	for rows.Next() {
		var id, status string
		var created int64
		if err := rows.Scan(&id, &status, &created); err != nil {
			return nil, err
		}
		m = append(m, obj{{"UserName", owner}, {"AccessKeyId", id}, {"Status", status}, {"CreateDate", time.UnixMilli(created)}})
	}
	return obj{{"AccessKeyMetadata", m}, {"IsTruncated", false}}, rows.Err()
}

func updateAccessKey(c *call) (obj, error) {
	owner, err := c.keyOwner()
	if err != nil {
		return nil, err
	}
	status := c.f.str("Status")
	if status != "Active" && status != "Inactive" {
		return nil, validationError("1 validation error detected: Value '%s' at 'status' failed to satisfy constraint: Member must satisfy enum value set: [Active, Inactive]", status)
	}
	id := c.f.str("AccessKeyId")
	res, err := c.tx.ExecContext(c.ctx, `UPDATE access_keys SET status=? WHERE account_id=? AND kind='user' AND user_name=? AND access_key=?`, status, c.account, owner, id)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, noSuchEntity("The Access Key with id %s cannot be found", id)
	}
	return nil, nil
}

func deleteAccessKey(c *call) (obj, error) {
	owner, err := c.keyOwner()
	if err != nil {
		return nil, err
	}
	id := c.f.str("AccessKeyId")
	res, err := c.tx.ExecContext(c.ctx, `DELETE FROM access_keys WHERE account_id=? AND kind='user' AND user_name=? AND access_key=?`, c.account, owner, id)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, noSuchEntity("The Access Key with id %s cannot be found", id)
	}
	return nil, nil
}

func getAccessKeyLastUsed(c *call) (obj, error) {
	id := c.f.str("AccessKeyId")
	var owner, svc, region string
	var used int64
	err := c.tx.QueryRowContext(c.ctx, `SELECT user_name, last_used, last_service, last_region FROM access_keys WHERE account_id=? AND kind='user' AND access_key=?`,
		c.account, id).Scan(&owner, &used, &svc, &region)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, noSuchEntity("The Access Key with id %s cannot be found", id)
	}
	if err != nil {
		return nil, err
	}
	last := obj{{"ServiceName", "N/A"}, {"Region", "N/A"}}
	if used > 0 {
		last = obj{{"LastUsedDate", time.UnixMilli(used)}, {"ServiceName", svc}, {"Region", region}}
	}
	return obj{{"UserName", owner}, {"AccessKeyLastUsed", last}}, nil
}

// ---------------------------------------------------------------- login profiles

func createLoginProfile(c *call) (obj, error) {
	u, err := c.user(c.f.str("UserName"))
	if err != nil {
		return nil, err
	}
	if u.Login != nil {
		return nil, alreadyExists("User %s already has password", u.Name)
	}
	u.Login = &LoginProfile{Created: c.now, ResetRequired: c.f.boolValue("PasswordResetRequired")}
	if err := c.saveUser(u); err != nil {
		return nil, err
	}
	return obj{{"LoginProfile", loginXML(u)}}, nil
}

func loginXML(u *User) obj {
	return obj{{"UserName", u.Name}, {"CreateDate", u.Login.Created}, {"PasswordResetRequired", u.Login.ResetRequired}}
}

func (c *call) loginUser() (*User, error) {
	u, err := c.user(c.f.str("UserName"))
	if err != nil {
		return nil, err
	}
	if u.Login == nil {
		return nil, noSuchEntity("Login profile for %s not found", u.Name)
	}
	return u, nil
}

func getLoginProfile(c *call) (obj, error) {
	u, err := c.loginUser()
	if err != nil {
		return nil, err
	}
	return obj{{"LoginProfile", loginXML(u)}}, nil
}

func updateLoginProfile(c *call) (obj, error) {
	u, err := c.loginUser()
	if err != nil {
		return nil, err
	}
	if c.f.has("PasswordResetRequired") {
		u.Login.ResetRequired = c.f.boolValue("PasswordResetRequired")
	}
	return nil, c.saveUser(u)
}

func deleteLoginProfile(c *call) (obj, error) {
	u, err := c.loginUser()
	if err != nil {
		return nil, err
	}
	u.Login = nil
	return nil, c.saveUser(u)
}

// ---------------------------------------------------------------- SSH public keys

func sshXML(u *User, k SSHKey, withBody bool) obj {
	o := obj{{"UserName", u.Name}, {"SSHPublicKeyId", k.ID}}
	if withBody {
		o = append(o, kv{"Fingerprint", k.Fingerprint}, kv{"SSHPublicKeyBody", k.Body})
	}
	return append(o, kv{"Status", k.Status}, kv{"UploadDate", k.Uploaded})
}

func uploadSSHPublicKey(c *call) (obj, error) {
	u, err := c.user(c.f.str("UserName"))
	if err != nil {
		return nil, err
	}
	body := c.f.str("SSHPublicKeyBody")
	sum := md5.Sum([]byte(body))
	var fp []string
	for _, b := range sum {
		fp = append(fp, fmt.Sprintf("%02x", b))
	}
	k := SSHKey{ID: randomID("APKA", 16), Body: body, Fingerprint: strings.Join(fp, ":"), Status: "Active", Uploaded: c.now}
	u.SSHKeys = append(u.SSHKeys, k)
	if err := c.saveUser(u); err != nil {
		return nil, err
	}
	return obj{{"SSHPublicKey", sshXML(u, k, true)}}, nil
}

func (c *call) sshKey() (*User, int, error) {
	u, err := c.user(c.f.str("UserName"))
	if err != nil {
		return nil, 0, err
	}
	id := c.f.str("SSHPublicKeyId")
	for i, k := range u.SSHKeys {
		if k.ID == id {
			return u, i, nil
		}
	}
	return nil, 0, noSuchEntity("The Public Key with id %s cannot be found", id)
}

func getSSHPublicKey(c *call) (obj, error) {
	u, i, err := c.sshKey()
	if err != nil {
		return nil, err
	}
	return obj{{"SSHPublicKey", sshXML(u, u.SSHKeys[i], true)}}, nil
}

func listSSHPublicKeys(c *call) (obj, error) {
	u, err := c.user(c.f.str("UserName"))
	if err != nil {
		return nil, err
	}
	m := members{}
	for _, k := range u.SSHKeys {
		m = append(m, sshXML(u, k, false))
	}
	return obj{{"SSHPublicKeys", m}, {"IsTruncated", false}}, nil
}

func updateSSHPublicKey(c *call) (obj, error) {
	u, i, err := c.sshKey()
	if err != nil {
		return nil, err
	}
	u.SSHKeys[i].Status = c.f.str("Status")
	return nil, c.saveUser(u)
}

func deleteSSHPublicKey(c *call) (obj, error) {
	u, i, err := c.sshKey()
	if err != nil {
		return nil, err
	}
	u.SSHKeys = append(u.SSHKeys[:i:i], u.SSHKeys[i+1:]...)
	return nil, c.saveUser(u)
}

// ---------------------------------------------------------------- signing certificates

func uploadSigningCertificate(c *call) (obj, error) {
	u, err := c.user(c.f.str("UserName"))
	if err != nil {
		return nil, err
	}
	body := c.f.str("CertificateBody")
	if !strings.Contains(body, "BEGIN CERTIFICATE") {
		return nil, newErr(400, "MalformedCertificate", "Certificate %s is malformed", body)
	}
	cert := SigningCert{ID: randomID("", 32), Body: body, Status: "Active", Uploaded: c.now}
	u.SigningCerts = append(u.SigningCerts, cert)
	if err := c.saveUser(u); err != nil {
		return nil, err
	}
	return obj{{"Certificate", certXML(u, cert)}}, nil
}

func certXML(u *User, cert SigningCert) obj {
	return obj{{"UserName", u.Name}, {"CertificateId", cert.ID}, {"CertificateBody", cert.Body}, {"Status", cert.Status}, {"UploadDate", cert.Uploaded}}
}

func (c *call) signingCert() (*User, int, error) {
	u, err := c.user(c.f.str("UserName"))
	if err != nil {
		return nil, 0, err
	}
	id := c.f.str("CertificateId")
	for i, cert := range u.SigningCerts {
		if cert.ID == id {
			return u, i, nil
		}
	}
	return nil, 0, noSuchEntity("The Certificate with id %s cannot be found.", id)
}

func listSigningCertificates(c *call) (obj, error) {
	u, err := c.user(c.f.str("UserName"))
	if err != nil {
		return nil, err
	}
	m := members{}
	for _, cert := range u.SigningCerts {
		m = append(m, certXML(u, cert))
	}
	return obj{{"Certificates", m}, {"IsTruncated", false}}, nil
}

func updateSigningCertificate(c *call) (obj, error) {
	u, i, err := c.signingCert()
	if err != nil {
		return nil, err
	}
	u.SigningCerts[i].Status = c.f.str("Status")
	return nil, c.saveUser(u)
}

func deleteSigningCertificate(c *call) (obj, error) {
	u, i, err := c.signingCert()
	if err != nil {
		return nil, err
	}
	u.SigningCerts = append(u.SigningCerts[:i:i], u.SigningCerts[i+1:]...)
	return nil, c.saveUser(u)
}

// ---------------------------------------------------------------- MFA devices

// VirtualMFA is a virtual MFA device.
type VirtualMFA struct {
	Serial   string
	Seed     string
	Created  time.Time
	Enabled  *time.Time `json:",omitempty"`
	UserName string     `json:",omitempty"`
	Tags     []Tag      `json:",omitempty"`
}

func createVirtualMFADevice(c *call) (obj, error) {
	path := c.f.str("Path")
	if path == "" {
		path = "/"
	}
	bad := !strings.HasPrefix(path, "/") && !strings.HasSuffix(path, "/")
	for _, part := range strings.Split(path, "/")[1:max(1, len(strings.Split(path, "/"))-1)] {
		if part == "" {
			bad = true
		}
	}
	if bad {
		return nil, validationError("The specified value for path is invalid. It must begin and end with / and contain only alphanumeric characters and/or / characters.")
	}
	if len(path) > 512 {
		return nil, validationError(`1 validation error detected: Value "%s" at "path" failed to satisfy constraint: Member must have length less than or equal to 512`, path)
	}
	serial := c.arn("mfa" + path + c.f.str("VirtualMFADeviceName"))
	var existing VirtualMFA
	if ok, err := load(c.ctx, c.tx, c.account, kMFA, serial, &existing); err != nil {
		return nil, err
	} else if ok {
		return nil, alreadyExists("MFADevice entity at the same path and name already exists.")
	}
	seed := make([]byte, 20)
	_, _ = rand.Read(seed)
	d := &VirtualMFA{Serial: serial, Seed: base64.StdEncoding.EncodeToString(seed), Created: c.now}
	tags, err := readTags(c.f, "Tags")
	if err != nil {
		return nil, err
	}
	d.Tags = tags
	if err := save(c.ctx, c.tx, c.account, kMFA, serial, d); err != nil {
		return nil, err
	}
	return obj{{"VirtualMFADevice", obj{{"SerialNumber", serial},
		{"Base32StringSeed", d.Seed},
		{"QRCodePNG", base64.StdEncoding.EncodeToString([]byte("otpauth://totp/" + serial))}}}}, nil
}

func deleteVirtualMFADevice(c *call) (obj, error) {
	serial := c.f.str("SerialNumber")
	var d VirtualMFA
	ok, err := load(c.ctx, c.tx, c.account, kMFA, serial, &d)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, noSuchEntity("VirtualMFADevice with serial number %s doesn't exist.", serial)
	}
	if d.UserName != "" {
		return nil, deleteConflict("MFA device is still in use.")
	}
	return nil, remove(c.ctx, c.tx, c.account, kMFA, serial)
}

func listVirtualMFADevices(c *call) (obj, error) {
	all, err := loadAll[VirtualMFA](c.ctx, c.tx, c.account, kMFA)
	if err != nil {
		return nil, err
	}
	status := c.f.str("AssignmentStatus")
	var list []*VirtualMFA
	for _, d := range all {
		if (status == "Assigned" && d.Enabled == nil) || (status == "Unassigned" && d.Enabled != nil) {
			continue
		}
		list = append(list, d)
	}
	if m := c.f.str("Marker"); m != "" {
		var n int
		if _, err := fmt.Sscanf(m, "%d", &n); err != nil || n > len(list) {
			return nil, validationError("Invalid Marker.")
		}
	}
	list, tail, err := page(c, list, 100)
	if err != nil {
		return nil, err
	}
	m := members{}
	for _, d := range list {
		o := obj{{"SerialNumber", d.Serial}}
		if d.Enabled != nil {
			if u, err := c.user(d.UserName); err == nil {
				o = append(o, kv{"User", userXML(u, true)})
			}
			o = append(o, kv{"EnableDate", *d.Enabled})
		}
		m = append(m, o)
	}
	return append(obj{{"VirtualMFADevices", m}}, tail...), nil
}

func enableMFADevice(c *call) (obj, error) {
	u, err := c.user(c.f.str("UserName"))
	if err != nil {
		return nil, err
	}
	serial := c.f.str("SerialNumber")
	for _, m := range u.MFA {
		if m.Serial == serial {
			return nil, alreadyExists("Device %s already exists", serial)
		}
	}
	u.MFA = append(u.MFA, MFABinding{Serial: serial, Enabled: c.now})
	var d VirtualMFA
	if ok, err := load(c.ctx, c.tx, c.account, kMFA, serial, &d); err != nil {
		return nil, err
	} else if ok {
		now := c.now
		d.Enabled, d.UserName = &now, u.Name
		if err := save(c.ctx, c.tx, c.account, kMFA, serial, &d); err != nil {
			return nil, err
		}
	}
	return nil, c.saveUser(u)
}

func deactivateMFADevice(c *call) (obj, error) {
	u, err := c.user(c.f.str("UserName"))
	if err != nil {
		return nil, err
	}
	serial := c.f.str("SerialNumber")
	found := false
	for i, m := range u.MFA {
		if m.Serial == serial {
			u.MFA = append(u.MFA[:i:i], u.MFA[i+1:]...)
			found = true
			break
		}
	}
	if !found {
		return nil, noSuchEntity("Device %s not found", serial)
	}
	var d VirtualMFA
	if ok, err := load(c.ctx, c.tx, c.account, kMFA, serial, &d); err != nil {
		return nil, err
	} else if ok {
		d.Enabled, d.UserName = nil, ""
		if err := save(c.ctx, c.tx, c.account, kMFA, serial, &d); err != nil {
			return nil, err
		}
	}
	return nil, c.saveUser(u)
}

func listMFADevices(c *call) (obj, error) {
	u, err := c.user(c.f.str("UserName"))
	if err != nil {
		return nil, err
	}
	m := members{}
	for _, d := range u.MFA {
		m = append(m, obj{{"UserName", u.Name}, {"SerialNumber", d.Serial}, {"EnableDate", d.Enabled}})
	}
	return obj{{"MFADevices", m}, {"IsTruncated", false}}, nil
}
