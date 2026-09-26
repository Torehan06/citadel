package iam

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

var policyARNPattern = regexp.MustCompile(`^arn:(aws|aws-cn|aws-us-gov|aws-iso|aws-iso-b|aws-eusc):iam::(aws|[0-9]*):policy/.*$`)

func (c *call) checkBoundary(arn string) error {
	if !policyARNPattern.MatchString(arn) {
		return newErr(400, "InvalidParameterValue", "Value (%s) for parameter PermissionsBoundary is invalid.", arn)
	}
	return nil
}

func (c *call) role(name string) (*Role, error) {
	var r Role
	ok, err := load(c.ctx, c.tx, c.account, kRole, nameKey(name), &r)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, noSuchEntity("Role %s not found", name)
	}
	return &r, nil
}

func (c *call) saveRole(r *Role) error {
	return save(c.ctx, c.tx, c.account, kRole, nameKey(r.Name), r)
}

func roleXML(r *Role, full bool) obj {
	o := obj{{"Path", r.Path}, {"RoleName", r.Name}, {"RoleId", r.ID}, {"Arn", r.ARN}, {"CreateDate", r.Created},
		{"AssumeRolePolicyDocument", encodeDocument(r.TrustPolicy)}}
	if r.Description != nil {
		o = append(o, kv{"Description", *r.Description})
	}
	o = append(o, kv{"MaxSessionDuration", r.maxSession()})
	if r.Boundary != "" {
		o = append(o, kv{"PermissionsBoundary", boundaryXML(r.Boundary)})
	}
	if len(r.Tags) > 0 {
		o = append(o, kv{"Tags", tagsXML(r.Tags)})
	}
	if full {
		last := obj{}
		if r.LastUsed != nil {
			last = obj{{"LastUsedDate", *r.LastUsed}, {"Region", r.LastUsedRegion}}
		}
		o = append(o, kv{"RoleLastUsed", last})
	}
	return o
}

func (r *Role) maxSession() int {
	if r.MaxSession == 0 {
		return 3600
	}
	return r.MaxSession
}

func readMaxSession(c *call) (int, error) {
	if !c.f.has("MaxSessionDuration") {
		return 0, nil
	}
	n, err := c.f.intValue("MaxSessionDuration", 3600)
	if err != nil {
		return 0, err
	}
	if n < 3600 || n > 43200 {
		return 0, validationError("1 validation error detected: Value '%d' at 'maxSessionDuration' failed to satisfy constraint: Member must have value between 3600 and 43200", n)
	}
	return n, nil
}

func createRole(c *call) (obj, error) {
	name, err := requireName(c, "RoleName")
	if err != nil {
		return nil, err
	}
	path, err := readPath(c, "Path")
	if err != nil {
		return nil, err
	}
	r, err := c.newRole(name, path, c.f.str("AssumeRolePolicyDocument"))
	if err != nil {
		return nil, err
	}
	if c.f.has("Description") {
		d := c.f.str("Description")
		r.Description = &d
	}
	if r.MaxSession, err = readMaxSession(c); err != nil {
		return nil, err
	}
	if r.Tags, err = readTags(c.f, "Tags"); err != nil {
		return nil, err
	}
	if b := c.f.str("PermissionsBoundary"); b != "" {
		if err := c.checkBoundary(b); err != nil {
			return nil, err
		}
		r.Boundary = b
	}
	if err := c.saveRole(r); err != nil {
		return nil, err
	}
	return obj{{"Role", roleXML(r, false)}}, nil
}

// newRole checks the name is free and builds a role. The trust policy is
// stored as given: a document that does not parse grants nothing when STS
// evaluates it.
func (c *call) newRole(name, path, trust string) (*Role, error) {
	var existing Role
	if ok, err := load(c.ctx, c.tx, c.account, kRole, nameKey(name), &existing); err != nil {
		return nil, err
	} else if ok {
		return nil, alreadyExists("Role with name %s already exists.", name)
	}
	return &Role{Path: path, Name: name, ID: randomID("AROA", 17), ARN: c.arn("role" + path + name), Created: c.now, TrustPolicy: trust}, nil
}

func getRole(c *call) (obj, error) {
	r, err := c.role(c.f.str("RoleName"))
	if err != nil {
		return nil, err
	}
	return obj{{"Role", roleXML(r, true)}}, nil
}

func listRoles(c *call) (obj, error) {
	roles, err := loadAll[Role](c.ctx, c.tx, c.account, kRole)
	if err != nil {
		return nil, err
	}
	prefix := c.f.str("PathPrefix")
	var list []*Role
	for _, r := range roles {
		if strings.HasPrefix(r.Path, prefix) {
			list = append(list, r)
		}
	}
	list, tail, err := page(c, list, 100)
	if err != nil {
		return nil, err
	}
	m := members{}
	for _, r := range list {
		m = append(m, roleXML(r, false))
	}
	return append(obj{{"Roles", m}}, tail...), nil
}

func updateRole(c *call) (obj, error) {
	r, err := c.role(c.f.str("RoleName"))
	if err != nil {
		return nil, err
	}
	if c.f.has("Description") {
		d := c.f.str("Description")
		r.Description = &d
	} else {
		r.Description = nil
	}
	if r.MaxSession, err = readMaxSession(c); err != nil {
		return nil, err
	}
	return obj{}, c.saveRole(r)
}

func updateRoleDescription(c *call) (obj, error) {
	r, err := c.role(c.f.str("RoleName"))
	if err != nil {
		return nil, err
	}
	d := c.f.str("Description")
	r.Description = &d
	if err := c.saveRole(r); err != nil {
		return nil, err
	}
	return obj{{"Role", roleXML(r, true)}}, nil
}

func updateAssumeRolePolicy(c *call) (obj, error) {
	r, err := c.role(c.f.str("RoleName"))
	if err != nil {
		return nil, err
	}
	doc := c.f.str("PolicyDocument")
	if err := ValidateTrustPolicy(doc); err != nil {
		return nil, err
	}
	r.TrustPolicy = doc
	return nil, c.saveRole(r)
}

func deleteRole(c *call) (obj, error) {
	r, err := c.role(c.f.str("RoleName"))
	if err != nil {
		return nil, err
	}
	profiles, err := loadAll[Profile](c.ctx, c.tx, c.account, kProfile)
	if err != nil {
		return nil, err
	}
	for _, p := range profiles {
		if contains(p.Roles, r.ID) {
			return nil, deleteConflict("Cannot delete entity, must remove roles from instance profile first.")
		}
	}
	switch {
	case len(r.Attached) > 0:
		return nil, deleteConflict("Cannot delete entity, must detach all policies first.")
	case len(r.Inline) > 0:
		return nil, deleteConflict("Cannot delete entity, must delete policies first.")
	}
	return nil, remove(c.ctx, c.tx, c.account, kRole, nameKey(r.Name))
}

func putRolePermissionsBoundary(c *call) (obj, error) {
	b := c.f.str("PermissionsBoundary")
	if err := c.checkBoundary(b); err != nil {
		return nil, err
	}
	r, err := c.role(c.f.str("RoleName"))
	if err != nil {
		return nil, err
	}
	r.Boundary = b
	return nil, c.saveRole(r)
}

func deleteRolePermissionsBoundary(c *call) (obj, error) {
	r, err := c.role(c.f.str("RoleName"))
	if err != nil {
		return nil, err
	}
	r.Boundary = ""
	return nil, c.saveRole(r)
}

func putUserPermissionsBoundary(c *call) (obj, error) {
	b := c.f.str("PermissionsBoundary")
	if err := c.checkBoundary(b); err != nil {
		return nil, err
	}
	u, err := c.user(c.f.str("UserName"))
	if err != nil {
		return nil, err
	}
	u.Boundary = b
	return nil, c.saveUser(u)
}

func deleteUserPermissionsBoundary(c *call) (obj, error) {
	u, err := c.user(c.f.str("UserName"))
	if err != nil {
		return nil, err
	}
	u.Boundary = ""
	return nil, c.saveUser(u)
}

func tagRole(c *call) (obj, error) {
	tags, err := readTags(c.f, "Tags")
	if err != nil {
		return nil, err
	}
	r, err := c.role(c.f.str("RoleName"))
	if err != nil {
		return nil, err
	}
	r.Tags = mergeTags(r.Tags, tags)
	if len(r.Tags) > 50 {
		return nil, limitExceeded("The number of tags has reached the maximum limit.")
	}
	return nil, c.saveRole(r)
}

func untagRole(c *call) (obj, error) {
	keys, err := readTagKeys(c.f)
	if err != nil {
		return nil, err
	}
	r, err := c.role(c.f.str("RoleName"))
	if err != nil {
		return nil, err
	}
	r.Tags = removeTags(r.Tags, keys)
	return nil, c.saveRole(r)
}

func listRoleTags(c *call) (obj, error) {
	r, err := c.role(c.f.str("RoleName"))
	if err != nil {
		return nil, err
	}
	tags, tail, err := page(c, r.Tags, 100)
	if err != nil {
		return nil, err
	}
	return append(obj{{"Tags", tagsXML(tags)}}, tail...), nil
}

// serviceRoleNames are the role-name stems AWS uses for service-linked roles
// whose service principal is not already in the right case.
var serviceRoleNames = map[string]string{
	"autoscaling":             "AutoScaling",
	"application-autoscaling": "ApplicationAutoScaling",
	"elasticbeanstalk":        "ElasticBeanstalk",
}

func createServiceLinkedRole(c *call) (obj, error) {
	svc := c.f.str("AWSServiceName")
	parts := strings.Split(svc, ".")
	if len(parts) < 3 {
		return nil, invalidInput("Service name %s is not valid.", svc)
	}
	service := parts[len(parts)-3]
	prefix := parts[0]
	stem := serviceRoleNames[service]
	if stem == "" {
		stem = service
	}
	if service != prefix {
		var b strings.Builder
		for _, w := range strings.Split(prefix, "-") {
			if w != "" {
				b.WriteString(strings.ToUpper(w[:1]) + strings.ToLower(w[1:]))
			}
		}
		stem += "_" + b.String()
	}
	name := "AWSServiceRoleFor" + stem
	if s := c.f.str("CustomSuffix"); s != "" {
		name += "_" + s
	}
	trust, _ := json.Marshal(map[string]any{
		"Version": "2012-10-17",
		"Statement": []any{map[string]any{
			"Action": []string{"sts:AssumeRole"}, "Effect": "Allow",
			"Principal": map[string]any{"Service": []string{svc}},
		}},
	})
	r, err := c.newRole(name, "/aws-service-role/"+svc+"/", string(trust))
	if err != nil {
		return nil, err
	}
	if c.f.has("Description") {
		d := c.f.str("Description")
		r.Description = &d
	}
	if err := c.saveRole(r); err != nil {
		return nil, err
	}
	return obj{{"Role", roleXML(r, false)}}, nil
}

func deleteServiceLinkedRole(c *call) (obj, error) {
	r, err := c.role(c.f.str("RoleName"))
	if err != nil {
		return nil, err
	}
	// Service-linked roles carry only the service's own policy; drop it with the role.
	if err := remove(c.ctx, c.tx, c.account, kRole, nameKey(r.Name)); err != nil {
		return nil, err
	}
	var b [16]byte
	_, _ = rand.Read(b[:])
	task := fmt.Sprintf("task/aws-service-role/%s/%s/%x-%x-%x-%x-%x", strings.TrimPrefix(strings.TrimSuffix(r.Path, "/"), "/aws-service-role/"), r.Name, b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
	return obj{{"DeletionTaskId", task}}, nil
}

func getServiceLinkedRoleDeletionStatus(c *call) (obj, error) {
	return obj{{"Status", "SUCCEEDED"}}, nil
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
