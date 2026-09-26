package iam

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// ---------------------------------------------------------------- instance profiles

func (c *call) profile(name string) (*Profile, error) {
	var p Profile
	ok, err := load(c.ctx, c.tx, c.account, kProfile, nameKey(name), &p)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, noSuchEntity("Instance profile %s not found", name)
	}
	return &p, nil
}

func (c *call) saveProfile(p *Profile) error {
	return save(c.ctx, c.tx, c.account, kProfile, nameKey(p.Name), p)
}

func (c *call) profileXML(p *Profile) (obj, error) {
	roles := members{}
	for _, id := range p.Roles {
		if r, err := c.roleByID(id); err == nil {
			roles = append(roles, roleXML(r, false))
		}
	}
	return obj{{"Path", p.Path}, {"InstanceProfileName", p.Name}, {"InstanceProfileId", p.ID}, {"Arn", p.ARN},
		{"CreateDate", p.Created}, {"Roles", roles}, {"Tags", tagsXML(p.Tags)}}, nil
}

func (c *call) roleByID(id string) (*Role, error) {
	roles, err := loadAll[Role](c.ctx, c.tx, c.account, kRole)
	if err != nil {
		return nil, err
	}
	for _, r := range roles {
		if r.ID == id {
			return r, nil
		}
	}
	return nil, noSuchEntity("Role %s not found", id)
}

func createInstanceProfile(c *call) (obj, error) {
	name, err := requireName(c, "InstanceProfileName")
	if err != nil {
		return nil, err
	}
	path, err := readPath(c, "Path")
	if err != nil {
		return nil, err
	}
	tags, err := readTags(c.f, "Tags")
	if err != nil {
		return nil, err
	}
	var existing Profile
	if ok, err := load(c.ctx, c.tx, c.account, kProfile, nameKey(name), &existing); err != nil {
		return nil, err
	} else if ok {
		return nil, alreadyExists("Instance Profile %s already exists.", name)
	}
	p := &Profile{Path: path, Name: name, ID: randomID("AIPA", 17), ARN: c.arn("instance-profile" + path + name), Created: c.now, Tags: tags}
	if err := c.saveProfile(p); err != nil {
		return nil, err
	}
	x, err := c.profileXML(p)
	return obj{{"InstanceProfile", x}}, err
}

func getInstanceProfile(c *call) (obj, error) {
	p, err := c.profile(c.f.str("InstanceProfileName"))
	if err != nil {
		return nil, err
	}
	x, err := c.profileXML(p)
	return obj{{"InstanceProfile", x}}, err
}

func deleteInstanceProfile(c *call) (obj, error) {
	p, err := c.profile(c.f.str("InstanceProfileName"))
	if err != nil {
		return nil, err
	}
	if len(p.Roles) > 0 {
		return nil, deleteConflict("Cannot delete entity, must remove roles from instance profile first.")
	}
	return nil, remove(c.ctx, c.tx, c.account, kProfile, nameKey(p.Name))
}

func (c *call) listProfiles(filter func(*Profile) bool) (obj, error) {
	all, err := loadAll[Profile](c.ctx, c.tx, c.account, kProfile)
	if err != nil {
		return nil, err
	}
	var list []*Profile
	for _, p := range all {
		if filter(p) {
			list = append(list, p)
		}
	}
	list, tail, err := page(c, list, 100)
	if err != nil {
		return nil, err
	}
	m := members{}
	for _, p := range list {
		x, err := c.profileXML(p)
		if err != nil {
			return nil, err
		}
		m = append(m, x)
	}
	return append(obj{{"InstanceProfiles", m}}, tail...), nil
}

func listInstanceProfiles(c *call) (obj, error) {
	prefix := c.f.str("PathPrefix")
	return c.listProfiles(func(p *Profile) bool { return strings.HasPrefix(p.Path, prefix) })
}

func listInstanceProfilesForRole(c *call) (obj, error) {
	r, err := c.role(c.f.str("RoleName"))
	if err != nil {
		return nil, err
	}
	return c.listProfiles(func(p *Profile) bool { return contains(p.Roles, r.ID) })
}

func addRoleToInstanceProfile(c *call) (obj, error) {
	p, err := c.profile(c.f.str("InstanceProfileName"))
	if err != nil {
		return nil, err
	}
	r, err := c.role(c.f.str("RoleName"))
	if err != nil {
		return nil, err
	}
	if len(p.Roles) > 0 {
		return nil, limitExceeded("Cannot exceed quota for InstanceSessionsPerInstanceProfile: 1")
	}
	p.Roles = append(p.Roles, r.ID)
	return nil, c.saveProfile(p)
}

func removeRoleFromInstanceProfile(c *call) (obj, error) {
	p, err := c.profile(c.f.str("InstanceProfileName"))
	if err != nil {
		return nil, err
	}
	r, err := c.role(c.f.str("RoleName"))
	if err != nil {
		return nil, err
	}
	if !contains(p.Roles, r.ID) {
		return nil, noSuchEntity("Role %s is not in instance profile %s.", r.Name, p.Name)
	}
	p.Roles = without(p.Roles, r.ID)
	return nil, c.saveProfile(p)
}

func tagInstanceProfile(c *call) (obj, error) {
	p, err := c.profile(c.f.str("InstanceProfileName"))
	if err != nil {
		return nil, err
	}
	tags, err := readTags(c.f, "Tags")
	if err != nil {
		return nil, err
	}
	p.Tags = mergeTags(p.Tags, tags)
	return nil, c.saveProfile(p)
}

func untagInstanceProfile(c *call) (obj, error) {
	p, err := c.profile(c.f.str("InstanceProfileName"))
	if err != nil {
		return nil, err
	}
	keys, err := readTagKeys(c.f)
	if err != nil {
		return nil, err
	}
	p.Tags = removeTags(p.Tags, keys)
	return nil, c.saveProfile(p)
}

func listInstanceProfileTags(c *call) (obj, error) {
	p, err := c.profile(c.f.str("InstanceProfileName"))
	if err != nil {
		return nil, err
	}
	return obj{{"Tags", tagsXML(p.Tags)}, {"IsTruncated", false}}, nil
}

// ---------------------------------------------------------------- identity providers

// SAMLProvider is a SAML identity provider.
type SAMLProvider struct {
	Name, ARN, Metadata string
	Created             time.Time
	Tags                []Tag `json:",omitempty"`
}

func createSAMLProvider(c *call) (obj, error) {
	name := c.f.str("Name")
	p := &SAMLProvider{Name: name, ARN: c.arn("saml-provider/" + name), Metadata: c.f.str("SAMLMetadataDocument"), Created: c.now}
	var err error
	if p.Tags, err = readTags(c.f, "Tags"); err != nil {
		return nil, err
	}
	var existing SAMLProvider
	if ok, err := load(c.ctx, c.tx, c.account, kSAML, p.ARN, &existing); err != nil {
		return nil, err
	} else if ok {
		return nil, alreadyExists("SAMLProvider %s already exists", name)
	}
	if err := save(c.ctx, c.tx, c.account, kSAML, p.ARN, p); err != nil {
		return nil, err
	}
	return obj{{"SAMLProviderArn", p.ARN}}, nil
}

func (c *call) samlProvider() (*SAMLProvider, error) {
	arn := c.f.str("SAMLProviderArn")
	var p SAMLProvider
	ok, err := load(c.ctx, c.tx, c.account, kSAML, arn, &p)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, noSuchEntity("SAMLProvider %s not found", arn)
	}
	return &p, nil
}

func getSAMLProvider(c *call) (obj, error) {
	p, err := c.samlProvider()
	if err != nil {
		return nil, err
	}
	o := obj{{"SAMLMetadataDocument", p.Metadata}, {"CreateDate", p.Created}, {"ValidUntil", p.Created.AddDate(100, 0, 0)}}
	if len(p.Tags) > 0 {
		o = append(o, kv{"Tags", tagsXML(p.Tags)})
	}
	return o, nil
}

func updateSAMLProvider(c *call) (obj, error) {
	p, err := c.samlProvider()
	if err != nil {
		return nil, err
	}
	p.Metadata = c.f.str("SAMLMetadataDocument")
	if err := save(c.ctx, c.tx, c.account, kSAML, p.ARN, p); err != nil {
		return nil, err
	}
	return obj{{"SAMLProviderArn", p.ARN}}, nil
}

func deleteSAMLProvider(c *call) (obj, error) {
	p, err := c.samlProvider()
	if err != nil {
		return nil, err
	}
	return nil, remove(c.ctx, c.tx, c.account, kSAML, p.ARN)
}

func listSAMLProviders(c *call) (obj, error) {
	all, err := loadAll[SAMLProvider](c.ctx, c.tx, c.account, kSAML)
	if err != nil {
		return nil, err
	}
	m := members{}
	for _, p := range all {
		m = append(m, obj{{"Arn", p.ARN}, {"ValidUntil", p.Created.AddDate(100, 0, 0)}, {"CreateDate", p.Created}})
	}
	return obj{{"SAMLProviderList", m}}, nil
}

// OIDCProvider is an OpenID Connect identity provider.
type OIDCProvider struct {
	URL, ARN    string
	ClientIDs   []string `json:",omitempty"`
	Thumbprints []string `json:",omitempty"`
	Created     time.Time
	Tags        []Tag `json:",omitempty"`
}

func createOpenIDConnectProvider(c *call) (obj, error) {
	raw := c.f.str("Url")
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, validationError("Invalid Open ID Connect Provider URL")
	}
	thumbs := c.f.list("ThumbprintList")
	if len(thumbs) > 5 {
		return nil, invalidInput("Thumbprint list must contain fewer than 5 entries.")
	}
	clients := c.f.list("ClientIDList")
	if len(clients) > 100 {
		return nil, limitExceeded("Cannot exceed quota for ClientIdsPerOpenIdConnectProvider: 100")
	}
	p := &OIDCProvider{URL: raw, ARN: c.arn("oidc-provider/" + u.Host + strings.TrimSuffix(u.Path, "/")), ClientIDs: clients, Thumbprints: thumbs, Created: c.now}
	if p.Tags, err = readTags(c.f, "Tags"); err != nil {
		return nil, err
	}
	var existing OIDCProvider
	if ok, err := load(c.ctx, c.tx, c.account, kOIDC, p.ARN, &existing); err != nil {
		return nil, err
	} else if ok {
		return nil, alreadyExists("Unknown")
	}
	if err := save(c.ctx, c.tx, c.account, kOIDC, p.ARN, p); err != nil {
		return nil, err
	}
	o := obj{{"OpenIDConnectProviderArn", p.ARN}}
	if len(p.Tags) > 0 {
		o = append(o, kv{"Tags", tagsXML(p.Tags)})
	}
	return o, nil
}

func (c *call) oidcProvider() (*OIDCProvider, error) {
	arn := c.f.str("OpenIDConnectProviderArn")
	var p OIDCProvider
	ok, err := load(c.ctx, c.tx, c.account, kOIDC, arn, &p)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, noSuchEntity("OpenIDConnect Provider not found for arn %s", arn)
	}
	return &p, nil
}

func getOpenIDConnectProvider(c *call) (obj, error) {
	p, err := c.oidcProvider()
	if err != nil {
		return nil, err
	}
	u, _ := url.Parse(p.URL)
	o := obj{{"Url", u.Host + u.Path}, {"ClientIDList", strMembers(p.ClientIDs)}, {"ThumbprintList", strMembers(p.Thumbprints)}, {"CreateDate", p.Created}}
	if len(p.Tags) > 0 {
		o = append(o, kv{"Tags", tagsXML(p.Tags)})
	}
	return o, nil
}

func deleteOpenIDConnectProvider(c *call) (obj, error) {
	arn := c.f.str("OpenIDConnectProviderArn")
	return nil, remove(c.ctx, c.tx, c.account, kOIDC, arn)
}

func listOpenIDConnectProviders(c *call) (obj, error) {
	all, err := loadAll[OIDCProvider](c.ctx, c.tx, c.account, kOIDC)
	if err != nil {
		return nil, err
	}
	m := members{}
	for _, p := range all {
		m = append(m, obj{{"Arn", p.ARN}})
	}
	return obj{{"OpenIDConnectProviderList", m}}, nil
}

func updateOpenIDConnectProviderThumbprint(c *call) (obj, error) {
	p, err := c.oidcProvider()
	if err != nil {
		return nil, err
	}
	p.Thumbprints = c.f.list("ThumbprintList")
	return nil, save(c.ctx, c.tx, c.account, kOIDC, p.ARN, p)
}

// ---------------------------------------------------------------- account settings

// Settings are the account-wide IAM settings.
type Settings struct {
	PasswordPolicy *PasswordPolicy `json:",omitempty"`
	Aliases        []string        `json:",omitempty"`
	Report         string          `json:",omitempty"` // credential report CSV
	ReportAt       time.Time       `json:",omitempty"`
}

type PasswordPolicy struct {
	AllowChange, HardExpiry                          bool
	MaxAge, MinLength, ReusePrevention               int
	RequireLower, RequireNumbers, RequireSymbols, Up bool
}

func (c *call) settings() (*Settings, error) {
	var s Settings
	_, err := load(c.ctx, c.tx, c.account, kAccount, "settings", &s)
	return &s, err
}

func (c *call) saveSettings(s *Settings) error {
	return save(c.ctx, c.tx, c.account, kAccount, "settings", s)
}

func updateAccountPasswordPolicy(c *call) (obj, error) {
	p := &PasswordPolicy{
		AllowChange: c.f.boolValue("AllowUsersToChangePassword"), HardExpiry: c.f.boolValue("HardExpiry"),
		RequireLower: c.f.boolValue("RequireLowercaseCharacters"), RequireNumbers: c.f.boolValue("RequireNumbers"),
		RequireSymbols: c.f.boolValue("RequireSymbols"), Up: c.f.boolValue("RequireUppercaseCharacters"),
	}
	var err error
	if p.MaxAge, err = c.f.intValue("MaxPasswordAge", 0); err != nil {
		return nil, err
	}
	if p.MinLength, err = c.f.intValue("MinimumPasswordLength", 6); err != nil {
		return nil, err
	}
	if p.ReusePrevention, err = c.f.intValue("PasswordReusePrevention", 0); err != nil {
		return nil, err
	}
	var errs []string
	check := func(key string, v, limit int) {
		if v > limit {
			errs = append(errs, fmt.Sprintf(`Value "%d" at "%s" failed to satisfy constraint: Member must have value less than or equal to %d`, v, key, limit))
		}
	}
	check("minimumPasswordLength", p.MinLength, 128)
	check("passwordReusePrevention", p.ReusePrevention, 24)
	check("maxPasswordAge", p.MaxAge, 1095)
	if len(errs) > 0 {
		plural := ""
		if len(errs) > 1 {
			plural = "s"
		}
		return nil, validationError("%d validation error%s detected: %s", len(errs), plural, strings.Join(errs, "; "))
	}
	s, err := c.settings()
	if err != nil {
		return nil, err
	}
	s.PasswordPolicy = p
	return nil, c.saveSettings(s)
}

func getAccountPasswordPolicy(c *call) (obj, error) {
	s, err := c.settings()
	if err != nil {
		return nil, err
	}
	p := s.PasswordPolicy
	if p == nil {
		return nil, noSuchEntity("The Password Policy with domain name %s cannot be found.", c.account)
	}
	o := obj{{"MinimumPasswordLength", p.MinLength}, {"RequireSymbols", p.RequireSymbols}, {"RequireNumbers", p.RequireNumbers},
		{"RequireUppercaseCharacters", p.Up}, {"RequireLowercaseCharacters", p.RequireLower},
		{"AllowUsersToChangePassword", p.AllowChange}, {"ExpirePasswords", p.MaxAge > 0}}
	o = append(o, kv{"MaxPasswordAge", p.MaxAge})
	if p.ReusePrevention > 0 {
		o = append(o, kv{"PasswordReusePrevention", p.ReusePrevention})
	}
	o = append(o, kv{"HardExpiry", p.HardExpiry})
	return obj{{"PasswordPolicy", o}}, nil
}

func deleteAccountPasswordPolicy(c *call) (obj, error) {
	s, err := c.settings()
	if err != nil {
		return nil, err
	}
	if s.PasswordPolicy == nil {
		return nil, noSuchEntity("The account policy with name PasswordPolicy cannot be found.")
	}
	s.PasswordPolicy = nil
	return nil, c.saveSettings(s)
}

func createAccountAlias(c *call) (obj, error) {
	s, err := c.settings()
	if err != nil {
		return nil, err
	}
	s.Aliases = []string{c.f.str("AccountAlias")}
	return nil, c.saveSettings(s)
}

func deleteAccountAlias(c *call) (obj, error) {
	s, err := c.settings()
	if err != nil {
		return nil, err
	}
	s.Aliases = nil
	return nil, c.saveSettings(s)
}

func listAccountAliases(c *call) (obj, error) {
	s, err := c.settings()
	if err != nil {
		return nil, err
	}
	return obj{{"AccountAliases", strMembers(s.Aliases)}, {"IsTruncated", false}}, nil
}

func getAccountSummary(c *call) (obj, error) {
	users, err := loadAll[User](c.ctx, c.tx, c.account, kUser)
	if err != nil {
		return nil, err
	}
	count := func(kind string) int {
		var n int
		_ = c.tx.QueryRowContext(c.ctx, `SELECT COUNT(*) FROM iam_entities WHERE account_id=? AND kind=?`, c.account, kind).Scan(&n)
		return n
	}
	att, _, err := c.attachments()
	if err != nil {
		return nil, err
	}
	inUse, mfaInUse := 0, 0
	for _, n := range att {
		inUse += n
	}
	for _, u := range users {
		mfaInUse += len(u.MFA)
	}
	vals := []kv{
		{"GroupPolicySizeQuota", 5120}, {"InstanceProfilesQuota", 1000}, {"Policies", count(kPolicy)},
		{"GroupsPerUserQuota", 10}, {"InstanceProfiles", count(kProfile)}, {"AttachedPoliciesPerUserQuota", 10},
		{"Users", len(users)}, {"PoliciesQuota", 1500}, {"Providers", count(kSAML) + count(kOIDC)},
		{"AccountMFAEnabled", 0}, {"AccessKeysPerUserQuota", 2}, {"AssumeRolePolicySizeQuota", 2048},
		{"PolicyVersionsInUseQuota", 10000}, {"GlobalEndpointTokenVersion", 1}, {"VersionsPerPolicyQuota", 5},
		{"AttachedPoliciesPerGroupQuota", 10}, {"PolicySizeQuota", 6144}, {"Groups", count(kGroup)},
		{"AccountSigningCertificatesPresent", 0}, {"UsersQuota", 5000}, {"ServerCertificatesQuota", 20},
		{"MFADevices", count(kMFA)}, {"UserPolicySizeQuota", 2048}, {"PolicyVersionsInUse", inUse},
		{"ServerCertificates", count(kCert)}, {"Roles", count(kRole)}, {"RolesQuota", 1000},
		{"SigningCertificatesPerUserQuota", 2}, {"MFADevicesInUse", mfaInUse}, {"RolePolicySizeQuota", 10240},
		{"AttachedPoliciesPerRoleQuota", 10}, {"AccountAccessKeysPresent", 0}, {"GroupsQuota", 300},
	}
	m := members{}
	for _, e := range vals {
		m = append(m, obj{{"key", e.K}, {"value", e.V}})
	}
	return obj{{"SummaryMap", entries(m)}}, nil
}

// entries renders a map as <entry><key/><value/></entry> elements.
type entries members

// ---------------------------------------------------------------- credential report

const reportHeader = "user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,access_key_2_last_used_region,access_key_2_last_used_service,cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated"

func generateCredentialReport(c *call) (obj, error) {
	s, err := c.settings()
	if err != nil {
		return nil, err
	}
	state := "COMPLETE"
	if s.Report == "" {
		state = "STARTED"
	}
	report, err := c.credentialReport()
	if err != nil {
		return nil, err
	}
	s.Report, s.ReportAt = report, c.now
	if err := c.saveSettings(s); err != nil {
		return nil, err
	}
	return obj{{"State", state}, {"Description", "No report exists. Starting a new report generation task"}}, nil
}

func getCredentialReport(c *call) (obj, error) {
	s, err := c.settings()
	if err != nil {
		return nil, err
	}
	if s.Report == "" {
		return nil, newErr(410, "ReportNotPresent", "Credential report not present")
	}
	return obj{{"Content", base64.StdEncoding.EncodeToString([]byte(s.Report))}, {"ReportFormat", "text/csv"}, {"GeneratedTime", s.ReportAt}}, nil
}

func (c *call) credentialReport() (string, error) {
	users, err := loadAll[User](c.ctx, c.tx, c.account, kUser)
	if err != nil {
		return "", err
	}
	const df = "2006-01-02T15:04:05+00:00"
	var b strings.Builder
	b.WriteString(reportHeader + "\n")
	for _, u := range users {
		pwEnabled, pwUsed, pwChanged := "false", "not_supported", "not_supported"
		if u.Login != nil {
			pwEnabled, pwUsed, pwChanged = "true", "no_information", u.Login.Created.UTC().Format(df)
			if u.PasswordLastUsed != nil {
				pwUsed = u.PasswordLastUsed.UTC().Format(df)
			}
		}
		type keyInfo struct{ active, rotated, used, region, svc string }
		keys := []keyInfo{{"false", "N/A", "N/A", "N/A", "N/A"}, {"false", "N/A", "N/A", "N/A", "N/A"}}
		rows, err := c.tx.QueryContext(c.ctx, `SELECT status, created, last_used, last_region, last_service FROM access_keys WHERE account_id=? AND kind='user' AND user_name=? ORDER BY created, rowid LIMIT 2`, c.account, u.Name)
		if err != nil {
			return "", err
		}
		for i := 0; rows.Next(); i++ {
			var status, region, svc string
			var created, used int64
			if err := rows.Scan(&status, &created, &used, &region, &svc); err != nil {
				rows.Close()
				return "", err
			}
			k := keyInfo{strings.ToLower(fmt.Sprint(status == "Active")), time.UnixMilli(created).UTC().Format(df), "N/A", "N/A", "N/A"}
			if used > 0 {
				k.used, k.region, k.svc = time.UnixMilli(used).UTC().Format(df), region, svc
			}
			keys[i] = k
		}
		rows.Close()
		certs := []string{"false", "N/A", "false", "N/A"}
		for i, cert := range u.SigningCerts {
			if i > 1 {
				break
			}
			certs[2*i], certs[2*i+1] = fmt.Sprint(cert.Status == "Active"), cert.Uploaded.UTC().Format(df)
		}
		fields := []string{u.Name, u.ARN, u.Created.UTC().Format(df), pwEnabled, pwUsed, pwChanged, "not_supported",
			fmt.Sprint(len(u.MFA) > 0),
			keys[0].active, keys[0].rotated, keys[0].used, keys[0].region, keys[0].svc,
			keys[1].active, keys[1].rotated, keys[1].used, keys[1].region, keys[1].svc}
		fields = append(fields, certs...)
		b.WriteString(strings.Join(fields, ",") + "\n")
	}
	return b.String(), nil
}

// ---------------------------------------------------------------- server certificates

// ServerCert is a server certificate.
type ServerCert struct {
	Name, Path, ID, ARN, Body, Chain string
	Uploaded                         time.Time
	Tags                             []Tag `json:",omitempty"`
}

func serverCertMeta(s *ServerCert) obj {
	return obj{{"Path", s.Path}, {"ServerCertificateName", s.Name}, {"ServerCertificateId", s.ID}, {"Arn", s.ARN},
		{"UploadDate", s.Uploaded}, {"Expiration", s.Uploaded.AddDate(1, 0, 0)}}
}

func uploadServerCertificate(c *call) (obj, error) {
	name := c.f.str("ServerCertificateName")
	path, err := readPath(c, "Path")
	if err != nil {
		return nil, err
	}
	var existing ServerCert
	if ok, err := load(c.ctx, c.tx, c.account, kCert, nameKey(name), &existing); err != nil {
		return nil, err
	} else if ok {
		return nil, alreadyExists("The Server Certificate with name %s already exists.", name)
	}
	s := &ServerCert{Name: name, Path: path, ID: randomID("ASCA", 17), ARN: c.arn("server-certificate" + path + name),
		Body: c.f.str("CertificateBody"), Chain: c.f.str("CertificateChain"), Uploaded: c.now}
	if s.Tags, err = readTags(c.f, "Tags"); err != nil {
		return nil, err
	}
	if err := save(c.ctx, c.tx, c.account, kCert, nameKey(name), s); err != nil {
		return nil, err
	}
	return obj{{"ServerCertificateMetadata", serverCertMeta(s)}}, nil
}

func (c *call) serverCert() (*ServerCert, error) {
	name := c.f.str("ServerCertificateName")
	var s ServerCert
	ok, err := load(c.ctx, c.tx, c.account, kCert, nameKey(name), &s)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, noSuchEntity("The Server Certificate with name %s cannot be found.", name)
	}
	return &s, nil
}

func getServerCertificate(c *call) (obj, error) {
	s, err := c.serverCert()
	if err != nil {
		return nil, err
	}
	o := obj{{"ServerCertificateMetadata", serverCertMeta(s)}, {"CertificateBody", s.Body}}
	if s.Chain != "" {
		o = append(o, kv{"CertificateChain", s.Chain})
	}
	return obj{{"ServerCertificate", o}}, nil
}

func deleteServerCertificate(c *call) (obj, error) {
	s, err := c.serverCert()
	if err != nil {
		return nil, err
	}
	return nil, remove(c.ctx, c.tx, c.account, kCert, nameKey(s.Name))
}

func listServerCertificates(c *call) (obj, error) {
	all, err := loadAll[ServerCert](c.ctx, c.tx, c.account, kCert)
	if err != nil {
		return nil, err
	}
	m := members{}
	for _, s := range all {
		m = append(m, serverCertMeta(s))
	}
	return obj{{"ServerCertificateMetadataList", m}, {"IsTruncated", false}}, nil
}

// ---------------------------------------------------------------- authorization details

func getAccountAuthorizationDetails(c *call) (obj, error) {
	filter := c.f.list("Filter")
	want := func(k string) bool { return len(filter) == 0 || contains(filter, k) }
	inlineList := func(order []string, inline map[string]string) members {
		m := members{}
		for _, n := range order {
			m = append(m, obj{{"PolicyName", n}, {"PolicyDocument", encodeDocument(inline[n])}})
		}
		return m
	}
	attachedList := func(arns []string) members {
		m := members{}
		for _, a := range arns {
			if p, err := c.policy(a); err == nil {
				m = append(m, obj{{"PolicyName", p.Name}, {"PolicyArn", a}})
			}
		}
		return m
	}
	users, groups, roles, policies := members{}, members{}, members{}, members{}
	allGroups, err := loadAll[Group](c.ctx, c.tx, c.account, kGroup)
	if err != nil {
		return nil, err
	}
	if want("User") {
		all, err := loadAll[User](c.ctx, c.tx, c.account, kUser)
		if err != nil {
			return nil, err
		}
		for _, u := range all {
			var names []string
			for _, g := range allGroups {
				if contains(u.Groups, g.ID) {
					names = append(names, g.Name)
				}
			}
			o := obj{{"Path", u.Path}, {"UserName", u.Name}, {"UserId", u.ID}, {"Arn", u.ARN}, {"CreateDate", u.Created},
				{"UserPolicyList", inlineList(u.InlineOrder, u.Inline)}, {"GroupList", strMembers(names)},
				{"AttachedManagedPolicies", attachedList(u.Attached)}}
			if u.Boundary != "" {
				o = append(o, kv{"PermissionsBoundary", boundaryXML(u.Boundary)})
			}
			o = append(o, kv{"Tags", tagsXML(u.Tags)})
			users = append(users, o)
		}
	}
	if want("Group") {
		for _, g := range allGroups {
			groups = append(groups, obj{{"Path", g.Path}, {"GroupName", g.Name}, {"GroupId", g.ID}, {"Arn", g.ARN}, {"CreateDate", g.Created},
				{"GroupPolicyList", inlineList(g.InlineOrder, g.Inline)}, {"AttachedManagedPolicies", attachedList(g.Attached)}})
		}
	}
	if want("Role") {
		all, err := loadAll[Role](c.ctx, c.tx, c.account, kRole)
		if err != nil {
			return nil, err
		}
		profiles, err := loadAll[Profile](c.ctx, c.tx, c.account, kProfile)
		if err != nil {
			return nil, err
		}
		for _, r := range all {
			ps := members{}
			for _, p := range profiles {
				if contains(p.Roles, r.ID) {
					x, err := c.profileXML(p)
					if err != nil {
						return nil, err
					}
					ps = append(ps, x)
				}
			}
			o := obj{{"Path", r.Path}, {"RoleName", r.Name}, {"RoleId", r.ID}, {"Arn", r.ARN}, {"CreateDate", r.Created},
				{"AssumeRolePolicyDocument", encodeDocument(r.TrustPolicy)}, {"InstanceProfileList", ps},
				{"RolePolicyList", inlineList(r.InlineOrder, r.Inline)}, {"AttachedManagedPolicies", attachedList(r.Attached)}}
			if r.Boundary != "" {
				o = append(o, kv{"PermissionsBoundary", boundaryXML(r.Boundary)})
			}
			o = append(o, kv{"Tags", tagsXML(r.Tags)}, kv{"RoleLastUsed", obj{}})
			roles = append(roles, o)
		}
	}
	if want("LocalManagedPolicy") || want("AWSManagedPolicy") {
		var list []*Policy
		if want("AWSManagedPolicy") {
			list = append(list, awsManagedList()...)
		}
		if want("LocalManagedPolicy") {
			local, err := loadAll[Policy](c.ctx, c.tx, c.account, kPolicy)
			if err != nil {
				return nil, err
			}
			list = append(list, local...)
		}
		att, bound, err := c.attachments()
		if err != nil {
			return nil, err
		}
		for _, p := range list {
			vs := members{}
			for _, v := range p.Versions {
				vs = append(vs, versionXML(v, p.Default, true))
			}
			policies = append(policies, obj{{"PolicyName", p.Name}, {"PolicyId", p.ID}, {"Arn", p.ARN}, {"Path", p.Path},
				{"DefaultVersionId", p.Default}, {"AttachmentCount", att[p.ARN]}, {"PermissionsBoundaryUsageCount", bound[p.ARN]},
				{"IsAttachable", true}, {"CreateDate", p.Created}, {"UpdateDate", p.Updated}, {"PolicyVersionList", vs}})
		}
	}
	return obj{{"UserDetailList", users}, {"GroupDetailList", groups}, {"RoleDetailList", roles}, {"Policies", policies}, {"IsTruncated", false}}, nil
}
