package iam

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// ---------------------------------------------------------------- managed policies

// managed is a managed policy as the API sees it: customer managed (stored)
// or AWS managed (built in, read-only).
type managed struct {
	*Policy
	aws bool
}

func (c *call) policy(arn string) (*managed, error) {
	if p := awsManaged(arn); p != nil {
		return &managed{p, true}, nil
	}
	var p Policy
	ok, err := load(c.ctx, c.tx, c.account, kPolicy, arn, &p)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, noSuchEntity("Policy %s not found", arn)
	}
	return &managed{&p, false}, nil
}

func (c *call) savePolicy(p *Policy) error { return save(c.ctx, c.tx, c.account, kPolicy, p.ARN, p) }

// attachments counts how many users, groups and roles attach each policy ARN.
func (c *call) attachments() (map[string]int, map[string]int, error) {
	att, bound := map[string]int{}, map[string]int{}
	users, err := loadAll[User](c.ctx, c.tx, c.account, kUser)
	if err != nil {
		return nil, nil, err
	}
	for _, u := range users {
		for _, a := range u.Attached {
			att[a]++
		}
		if u.Boundary != "" {
			bound[u.Boundary]++
		}
	}
	groups, err := loadAll[Group](c.ctx, c.tx, c.account, kGroup)
	if err != nil {
		return nil, nil, err
	}
	for _, g := range groups {
		for _, a := range g.Attached {
			att[a]++
		}
	}
	roles, err := loadAll[Role](c.ctx, c.tx, c.account, kRole)
	if err != nil {
		return nil, nil, err
	}
	for _, r := range roles {
		for _, a := range r.Attached {
			att[a]++
		}
		if r.Boundary != "" {
			bound[r.Boundary]++
		}
	}
	return att, bound, nil
}

func policyXML(p *Policy, attached, boundaries int, withTags bool) obj {
	o := obj{{"PolicyName", p.Name}, {"PolicyId", p.ID}, {"Arn", p.ARN}, {"Path", p.Path},
		{"DefaultVersionId", p.Default}, {"AttachmentCount", attached},
		{"PermissionsBoundaryUsageCount", boundaries}, {"IsAttachable", true}}
	if p.Description != "" {
		o = append(o, kv{"Description", p.Description})
	}
	o = append(o, kv{"CreateDate", p.Created}, kv{"UpdateDate", p.Updated})
	if withTags && len(p.Tags) > 0 {
		o = append(o, kv{"Tags", tagsXML(p.Tags)})
	}
	return o
}

func createPolicy(c *call) (obj, error) {
	name, err := requireName(c, "PolicyName")
	if err != nil {
		return nil, err
	}
	path, err := readPath(c, "Path")
	if err != nil {
		return nil, err
	}
	doc := c.f.str("PolicyDocument")
	if err := ValidatePolicy(doc); err != nil {
		return nil, err
	}
	tags, err := readTags(c.f, "Tags")
	if err != nil {
		return nil, err
	}
	all, err := loadAll[Policy](c.ctx, c.tx, c.account, kPolicy)
	if err != nil {
		return nil, err
	}
	for _, p := range all {
		if strings.EqualFold(p.Name, name) {
			return nil, alreadyExists("A policy called %s already exists. Duplicate names are not allowed.", name)
		}
	}
	p := &Policy{Path: path, Name: name, ID: randomID("ANPA", 17), ARN: c.arn("policy" + path + name),
		Description: c.f.str("Description"), Created: c.now, Updated: c.now, Default: "v1",
		Versions: []PolicyVersion{{ID: "v1", Document: doc, Created: c.now}}, NextVersion: 2, Tags: tags}
	if err := c.savePolicy(p); err != nil {
		return nil, err
	}
	return obj{{"Policy", policyXML(p, 0, 0, true)}}, nil
}

func getPolicy(c *call) (obj, error) {
	p, err := c.policy(c.f.str("PolicyArn"))
	if err != nil {
		return nil, err
	}
	att, bound, err := c.attachments()
	if err != nil {
		return nil, err
	}
	return obj{{"Policy", policyXML(p.Policy, att[p.ARN], bound[p.ARN], true)}}, nil
}

func deletePolicy(c *call) (obj, error) {
	p, err := c.policy(c.f.str("PolicyArn"))
	if err != nil {
		return nil, err
	}
	if p.aws {
		return nil, invalidInput("Cannot delete an AWS managed policy.")
	}
	att, _, err := c.attachments()
	if err != nil {
		return nil, err
	}
	if att[p.ARN] > 0 {
		return nil, deleteConflict("Cannot delete a policy attached to entities.")
	}
	return nil, remove(c.ctx, c.tx, c.account, kPolicy, p.ARN)
}

func listPolicies(c *call) (obj, error) {
	scope := c.f.str("Scope")
	var list []*Policy
	if scope == "" || scope == "All" || scope == "AWS" {
		list = append(list, awsManagedList()...)
	}
	if scope == "" || scope == "All" || scope == "Local" {
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
	prefix := c.f.str("PathPrefix")
	only := c.f.boolValue("OnlyAttached")
	var filtered []*Policy
	for _, p := range list {
		if strings.HasPrefix(p.Path, prefix) && (!only || att[p.ARN] > 0) {
			filtered = append(filtered, p)
		}
	}
	sort.SliceStable(filtered, func(i, j int) bool { return filtered[i].Name < filtered[j].Name })
	filtered, tail, err := page(c, filtered, 100)
	if err != nil {
		return nil, err
	}
	m := members{}
	for _, p := range filtered {
		m = append(m, policyXML(p, att[p.ARN], bound[p.ARN], false))
	}
	return append(obj{{"Policies", m}}, tail...), nil
}

func versionXML(v PolicyVersion, def string, withDoc bool) obj {
	o := obj{}
	if withDoc {
		o = append(o, kv{"Document", encodeDocument(v.Document)})
	}
	return append(o, kv{"VersionId", v.ID}, kv{"IsDefaultVersion", v.ID == def}, kv{"CreateDate", v.Created})
}

func (c *call) customerPolicy() (*Policy, error) {
	p, err := c.policy(c.f.str("PolicyArn"))
	if err != nil {
		return nil, err
	}
	if p.aws {
		return nil, invalidInput("Cannot modify an AWS managed policy.")
	}
	return p.Policy, nil
}

func createPolicyVersion(c *call) (obj, error) {
	doc := c.f.str("PolicyDocument")
	if err := ValidatePolicy(doc); err != nil {
		return nil, err
	}
	p, err := c.customerPolicy()
	if err != nil {
		return nil, err
	}
	if len(p.Versions) >= 5 {
		return nil, limitExceeded("A managed policy can have up to 5 versions. Before you create a new version, you must delete an existing version.")
	}
	v := PolicyVersion{ID: "v" + strconv.Itoa(p.NextVersion), Document: doc, Created: c.now}
	p.NextVersion++
	p.Versions = append(p.Versions, v)
	if c.f.boolValue("SetAsDefault") {
		p.Default = v.ID
		p.Updated = c.now
	}
	if err := c.savePolicy(p); err != nil {
		return nil, err
	}
	return obj{{"PolicyVersion", versionXML(v, p.Default, false)}}, nil
}

func getPolicyVersion(c *call) (obj, error) {
	p, err := c.policy(c.f.str("PolicyArn"))
	if err != nil {
		return nil, err
	}
	id := c.f.str("VersionId")
	for _, v := range p.Versions {
		if v.ID == id {
			return obj{{"PolicyVersion", versionXML(v, p.Default, true)}}, nil
		}
	}
	return nil, noSuchEntity("Policy %s version %s does not exist or is not attachable.", p.ARN, id)
}

func listPolicyVersions(c *call) (obj, error) {
	p, err := c.policy(c.f.str("PolicyArn"))
	if err != nil {
		return nil, err
	}
	vs, tail, err := page(c, p.Versions, 100)
	if err != nil {
		return nil, err
	}
	m := members{}
	for _, v := range vs {
		m = append(m, versionXML(v, p.Default, true))
	}
	return append(obj{{"Versions", m}}, tail...), nil
}

func deletePolicyVersion(c *call) (obj, error) {
	p, err := c.customerPolicy()
	if err != nil {
		return nil, err
	}
	id := c.f.str("VersionId")
	if id == p.Default {
		return nil, deleteConflict("Cannot delete the default version of a policy.")
	}
	for i, v := range p.Versions {
		if v.ID == id {
			p.Versions = append(p.Versions[:i:i], p.Versions[i+1:]...)
			return nil, c.savePolicy(p)
		}
	}
	return nil, noSuchEntity("Policy %s version %s does not exist or is not attachable.", p.ARN, id)
}

var versionIDPattern = regexp.MustCompile(`^v[1-9][0-9]*(\.[A-Za-z0-9-]*)?$`)

func setDefaultPolicyVersion(c *call) (obj, error) {
	id := c.f.str("VersionId")
	if !versionIDPattern.MatchString(id) {
		return nil, validationError(`Value '%s' at 'versionId' failed to satisfy constraint: Member must satisfy regular expression pattern: v[1-9][0-9]*(\.[A-Za-z0-9-]*)?`, id)
	}
	p, err := c.customerPolicy()
	if err != nil {
		return nil, err
	}
	for _, v := range p.Versions {
		if v.ID == id {
			p.Default = id
			p.Updated = c.now
			return nil, c.savePolicy(p)
		}
	}
	return nil, noSuchEntity("Policy %s version %s does not exist or is not attachable.", p.ARN, id)
}

func tagPolicy(c *call) (obj, error) {
	tags, err := readTags(c.f, "Tags")
	if err != nil {
		return nil, err
	}
	p, err := c.customerPolicy()
	if err != nil {
		return nil, err
	}
	p.Tags = mergeTags(p.Tags, tags)
	if len(p.Tags) > 50 {
		return nil, validationError("1 validation error detected: Value '%s' at 'tags' failed to satisfy constraint: Member must have length less than or equal to 50.", tagsString(p.Tags))
	}
	return nil, c.savePolicy(p)
}

func untagPolicy(c *call) (obj, error) {
	keys, err := readTagKeys(c.f)
	if err != nil {
		return nil, err
	}
	p, err := c.customerPolicy()
	if err != nil {
		return nil, err
	}
	p.Tags = removeTags(p.Tags, keys)
	return nil, c.savePolicy(p)
}

func listPolicyTags(c *call) (obj, error) {
	p, err := c.policy(c.f.str("PolicyArn"))
	if err != nil {
		return nil, err
	}
	tags, tail, err := page(c, p.Tags, 100)
	if err != nil {
		return nil, err
	}
	return append(obj{{"Tags", tagsXML(tags)}}, tail...), nil
}

// ---------------------------------------------------------------- principals with policies

// holder is a user, group or role: something with inline and attached policies.
type holder struct {
	kind, name string
	inline     *map[string]string
	order      *[]string
	attached   *[]string
	save       func() error
	missing    func(policy string) error // error for an unknown inline policy
}

func (c *call) holder(kind string) (*holder, error) {
	switch kind {
	case kUser:
		u, err := c.user(c.f.str("UserName"))
		if err != nil {
			return nil, err
		}
		return &holder{kind, u.Name, &u.Inline, &u.InlineOrder, &u.Attached, func() error { return c.saveUser(u) },
			func(p string) error { return noSuchEntity("The user policy with name %s cannot be found.", p) }}, nil
	case kGroup:
		g, err := c.group(c.f.str("GroupName"))
		if err != nil {
			return nil, err
		}
		return &holder{kind, g.Name, &g.Inline, &g.InlineOrder, &g.Attached, func() error { return c.saveGroup(g) },
			func(p string) error { return noSuchEntity("The group policy with name %s cannot be found.", p) }}, nil
	default:
		r, err := c.role(c.f.str("RoleName"))
		if err != nil {
			return nil, err
		}
		return &holder{kind, r.Name, &r.Inline, &r.InlineOrder, &r.Attached, func() error { return c.saveRole(r) },
			func(p string) error { return noSuchEntity("The role policy with name %s cannot be found.", p) }}, nil
	}
}

var holderField = map[string]string{kUser: "UserName", kGroup: "GroupName", kRole: "RoleName"}

func putInlinePolicy(kind string) opFunc {
	return func(c *call) (obj, error) {
		h, err := c.holder(kind)
		if err != nil {
			return nil, err
		}
		name, err := requireName(c, "PolicyName")
		if err != nil {
			return nil, err
		}
		doc := c.f.str("PolicyDocument")
		if err := ValidatePolicy(doc); err != nil {
			return nil, err
		}
		putInline(h.inline, h.order, name, doc)
		return nil, h.save()
	}
}

func getInlinePolicy(kind string) opFunc {
	return func(c *call) (obj, error) {
		h, err := c.holder(kind)
		if err != nil {
			return nil, err
		}
		name := c.f.str("PolicyName")
		doc, ok := (*h.inline)[name]
		if !ok {
			return nil, h.missing(name)
		}
		return obj{{holderField[kind], h.name}, {"PolicyName", name}, {"PolicyDocument", encodeDocument(doc)}}, nil
	}
}

func deleteInlinePolicy(kind string) opFunc {
	return func(c *call) (obj, error) {
		h, err := c.holder(kind)
		if err != nil {
			return nil, err
		}
		name := c.f.str("PolicyName")
		if !deleteInline(*h.inline, h.order, name) {
			return nil, h.missing(name)
		}
		return nil, h.save()
	}
}

func listInlinePolicies(kind string) opFunc {
	return func(c *call) (obj, error) {
		h, err := c.holder(kind)
		if err != nil {
			return nil, err
		}
		names, tail, err := page(c, *h.order, 100)
		if err != nil {
			return nil, err
		}
		return append(obj{{"PolicyNames", strMembers(names)}}, tail...), nil
	}
}

func attachPolicy(kind string) opFunc {
	return func(c *call) (obj, error) {
		h, err := c.holder(kind)
		if err != nil {
			return nil, err
		}
		arn := c.f.str("PolicyArn")
		if _, err := c.policy(arn); err != nil {
			return nil, noSuchEntity("Policy %s does not exist or is not attachable.", arn)
		}
		if !contains(*h.attached, arn) {
			*h.attached = append(*h.attached, arn)
		}
		return nil, h.save()
	}
}

func detachPolicy(kind string) opFunc {
	return func(c *call) (obj, error) {
		h, err := c.holder(kind)
		if err != nil {
			return nil, err
		}
		arn := c.f.str("PolicyArn")
		if !contains(*h.attached, arn) {
			return nil, noSuchEntity("Policy %s was not found.", arn)
		}
		*h.attached = without(*h.attached, arn)
		return nil, h.save()
	}
}

func listAttachedPolicies(kind string) opFunc {
	return func(c *call) (obj, error) {
		h, err := c.holder(kind)
		if err != nil {
			return nil, err
		}
		prefix := c.f.str("PathPrefix")
		var list []*Policy
		for _, arn := range *h.attached {
			p, err := c.policy(arn)
			if err != nil {
				continue
			}
			if strings.HasPrefix(p.Path, prefix) {
				list = append(list, p.Policy)
			}
		}
		sort.SliceStable(list, func(i, j int) bool { return list[i].Name < list[j].Name })
		list, tail, err := page(c, list, 100)
		if err != nil {
			return nil, err
		}
		m := members{}
		for _, p := range list {
			m = append(m, obj{{"PolicyName", p.Name}, {"PolicyArn", p.ARN}})
		}
		return append(obj{{"AttachedPolicies", m}}, tail...), nil
	}
}

func listEntitiesForPolicy(c *call) (obj, error) {
	arn := c.f.str("PolicyArn")
	if _, err := c.policy(arn); err != nil {
		return nil, err
	}
	filter := c.f.str("EntityFilter")
	prefix := c.f.str("PathPrefix")
	want := func(kind string) bool { return filter == "" || filter == kind }
	users, groups, roles := members{}, members{}, members{}
	if want("User") {
		all, err := loadAll[User](c.ctx, c.tx, c.account, kUser)
		if err != nil {
			return nil, err
		}
		for _, u := range all {
			if contains(u.Attached, arn) && strings.HasPrefix(u.Path, prefix) {
				users = append(users, obj{{"UserName", u.Name}, {"UserId", u.ID}})
			}
		}
	}
	if want("Group") {
		all, err := loadAll[Group](c.ctx, c.tx, c.account, kGroup)
		if err != nil {
			return nil, err
		}
		for _, g := range all {
			if contains(g.Attached, arn) && strings.HasPrefix(g.Path, prefix) {
				groups = append(groups, obj{{"GroupName", g.Name}, {"GroupId", g.ID}})
			}
		}
	}
	if want("Role") {
		all, err := loadAll[Role](c.ctx, c.tx, c.account, kRole)
		if err != nil {
			return nil, err
		}
		for _, r := range all {
			if contains(r.Attached, arn) && strings.HasPrefix(r.Path, prefix) {
				roles = append(roles, obj{{"RoleName", r.Name}, {"RoleId", r.ID}})
			}
		}
	}
	return obj{{"PolicyGroups", groups}, {"PolicyUsers", users}, {"PolicyRoles", roles}, {"IsTruncated", false}}, nil
}
