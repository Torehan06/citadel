package iam

import (
	"strings"
)

func validatePath(p string) error {
	if len(p) > 512 {
		return validationError(`1 validation error detected: Value "%s" at "path" failed to satisfy constraint: Member must have length less than or equal to 512`, p)
	}
	if !strings.HasPrefix(p, "/") || !strings.HasSuffix(p, "/") {
		return validationError("The specified value for path is invalid. It must begin and end with / and contain only alphanumeric characters and/or / characters.")
	}
	return nil
}

func readPath(c *call, param string) (string, error) {
	p := c.f.str(param)
	if p == "" {
		return "/", nil
	}
	return p, validatePath(p)
}

func requireName(c *call, param string) (string, error) {
	n := c.f.str(param)
	if n == "" {
		return "", validationError("1 validation error detected: Value null at '%s' failed to satisfy constraint: Member must not be null", lowerFirst(param))
	}
	return n, nil
}

func lowerFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToLower(s[:1]) + s[1:]
}

// ---------------------------------------------------------------- users

func (c *call) user(name string) (*User, error) {
	var u User
	ok, err := load(c.ctx, c.tx, c.account, kUser, nameKey(name), &u)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, noSuchEntity("The user with name %s cannot be found.", name)
	}
	return &u, nil
}

func (c *call) saveUser(u *User) error {
	return save(c.ctx, c.tx, c.account, kUser, nameKey(u.Name), u)
}

func userXML(u *User, withTags bool) obj {
	o := obj{{"Path", u.Path}, {"UserName", u.Name}, {"UserId", u.ID}, {"Arn", u.ARN}, {"CreateDate", u.Created}}
	if u.PasswordLastUsed != nil {
		o = append(o, kv{"PasswordLastUsed", *u.PasswordLastUsed})
	}
	if u.Boundary != "" {
		o = append(o, kv{"PermissionsBoundary", boundaryXML(u.Boundary)})
	}
	if withTags && len(u.Tags) > 0 {
		o = append(o, kv{"Tags", tagsXML(u.Tags)})
	}
	return o
}

func boundaryXML(arn string) obj {
	return obj{{"PermissionsBoundaryType", "PermissionsBoundaryPolicy"}, {"PermissionsBoundaryArn", arn}}
}

func createUser(c *call) (obj, error) {
	name, err := requireName(c, "UserName")
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
	var existing User
	if ok, err := load(c.ctx, c.tx, c.account, kUser, nameKey(name), &existing); err != nil {
		return nil, err
	} else if ok {
		return nil, alreadyExists("User %s already exists", name)
	}
	u := &User{Path: path, Name: name, ID: randomID("AIDA", 17), ARN: c.arn("user" + path + name), Created: c.now, Tags: tags}
	if b := c.f.str("PermissionsBoundary"); b != "" {
		if err := c.checkBoundary(b); err != nil {
			return nil, err
		}
		u.Boundary = b
	}
	if err := c.saveUser(u); err != nil {
		return nil, err
	}
	return obj{{"User", userXML(u, true)}}, nil
}

func getUser(c *call) (obj, error) {
	name := c.f.str("UserName")
	if name == "" {
		return obj{{"User", c.callerAsUser()}}, nil
	}
	u, err := c.user(name)
	if err != nil {
		return nil, err
	}
	return obj{{"User", userXML(u, true)}}, nil
}

// callerAsUser describes the caller when GetUser names no user.
func (c *call) callerAsUser() obj {
	switch c.who.Kind {
	case "user":
		if u, err := c.user(c.who.UserName); err == nil {
			return userXML(u, true)
		}
	}
	return obj{{"UserId", c.account}, {"Arn", "arn:aws:iam::" + c.account + ":root"}, {"CreateDate", c.now}, {"Path", "/"}, {"UserName", ""}}
}

func listUsers(c *call) (obj, error) {
	users, err := loadAll[User](c.ctx, c.tx, c.account, kUser)
	if err != nil {
		return nil, err
	}
	prefix := c.f.str("PathPrefix")
	var list []*User
	for _, u := range users {
		if strings.HasPrefix(u.Path, prefix) {
			list = append(list, u)
		}
	}
	list, tail, err := page(c, list, 100)
	if err != nil {
		return nil, err
	}
	m := members{}
	for _, u := range list {
		m = append(m, userXML(u, false))
	}
	return append(obj{{"Users", m}}, tail...), nil
}

func updateUser(c *call) (obj, error) {
	name, err := requireName(c, "UserName")
	if err != nil {
		return nil, err
	}
	u, err := c.user(name)
	if err != nil {
		return nil, err
	}
	oldKey := nameKey(u.Name)
	if p := c.f.str("NewPath"); p != "" {
		if err := validatePath(p); err != nil {
			return nil, err
		}
		u.Path = p
	}
	if n := c.f.str("NewUserName"); n != "" && n != u.Name {
		if nameKey(n) != oldKey {
			var other User
			if ok, err := load(c.ctx, c.tx, c.account, kUser, nameKey(n), &other); err != nil {
				return nil, err
			} else if ok {
				return nil, alreadyExists("User %s already exists", n)
			}
		}
		u.Name = n
		if _, err := c.tx.ExecContext(c.ctx, `UPDATE access_keys SET user_name=? WHERE account_id=? AND kind='user' AND user_name=?`, n, c.account, name); err != nil {
			return nil, err
		}
	}
	u.ARN = c.arn("user" + u.Path + u.Name)
	return nil, rename(c.ctx, c.tx, c.account, kUser, oldKey, nameKey(u.Name), u)
}

func deleteUser(c *call) (obj, error) {
	name, err := requireName(c, "UserName")
	if err != nil {
		return nil, err
	}
	u, err := c.user(name)
	if err != nil {
		return nil, err
	}
	var keys int
	if err := c.tx.QueryRowContext(c.ctx, `SELECT COUNT(*) FROM access_keys WHERE account_id=? AND kind='user' AND user_name=?`, c.account, u.Name).Scan(&keys); err != nil {
		return nil, err
	}
	switch {
	case len(u.Attached) > 0:
		return nil, deleteConflict("Cannot delete entity, must detach all policies first.")
	case len(u.Inline) > 0:
		return nil, deleteConflict("Cannot delete entity, must delete policies first.")
	case keys > 0:
		return nil, deleteConflict("Cannot delete entity, must delete access keys first.")
	case u.Login != nil:
		return nil, deleteConflict("Cannot delete entity, must delete login profile first.")
	case len(u.Groups) > 0:
		return nil, deleteConflict("Cannot delete entity, must remove users from group first.")
	case len(u.MFA) > 0:
		return nil, deleteConflict("Cannot delete entity, must delete MFA device first.")
	case len(u.SSHKeys) > 0:
		return nil, deleteConflict("Cannot delete entity, must delete SSH public keys first.")
	case len(u.SigningCerts) > 0:
		return nil, deleteConflict("Cannot delete entity, must delete signing certificates first.")
	}
	return nil, remove(c.ctx, c.tx, c.account, kUser, nameKey(u.Name))
}

func tagUser(c *call) (obj, error) {
	u, err := c.user(c.f.str("UserName"))
	if err != nil {
		return nil, err
	}
	tags, err := readTags(c.f, "Tags")
	if err != nil {
		return nil, err
	}
	u.Tags = mergeTags(u.Tags, tags)
	if len(u.Tags) > 50 {
		return nil, limitExceeded("The number of tags has reached the maximum limit.")
	}
	return nil, c.saveUser(u)
}

func untagUser(c *call) (obj, error) {
	u, err := c.user(c.f.str("UserName"))
	if err != nil {
		return nil, err
	}
	keys, err := readTagKeys(c.f)
	if err != nil {
		return nil, err
	}
	u.Tags = removeTags(u.Tags, keys)
	return nil, c.saveUser(u)
}

func listUserTags(c *call) (obj, error) {
	u, err := c.user(c.f.str("UserName"))
	if err != nil {
		return nil, err
	}
	tags, tail, err := page(c, u.Tags, 100)
	if err != nil {
		return nil, err
	}
	return append(obj{{"Tags", tagsXML(tags)}}, tail...), nil
}

// ---------------------------------------------------------------- groups

func (c *call) group(name string) (*Group, error) {
	var g Group
	ok, err := load(c.ctx, c.tx, c.account, kGroup, nameKey(name), &g)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, noSuchEntity("Group %s not found", name)
	}
	return &g, nil
}

func (c *call) saveGroup(g *Group) error {
	return save(c.ctx, c.tx, c.account, kGroup, nameKey(g.Name), g)
}

func groupXML(g *Group) obj {
	return obj{{"Path", g.Path}, {"GroupName", g.Name}, {"GroupId", g.ID}, {"Arn", g.ARN}, {"CreateDate", g.Created}}
}

func createGroup(c *call) (obj, error) {
	name, err := requireName(c, "GroupName")
	if err != nil {
		return nil, err
	}
	path, err := readPath(c, "Path")
	if err != nil {
		return nil, err
	}
	var existing Group
	if ok, err := load(c.ctx, c.tx, c.account, kGroup, nameKey(name), &existing); err != nil {
		return nil, err
	} else if ok {
		return nil, alreadyExists("Group %s already exists", name)
	}
	g := &Group{Path: path, Name: name, ID: randomID("AGPA", 17), ARN: c.arn("group" + path + name), Created: c.now}
	if err := c.saveGroup(g); err != nil {
		return nil, err
	}
	return obj{{"Group", groupXML(g)}}, nil
}

func (c *call) groupMembers(g *Group) ([]*User, error) {
	users, err := loadAll[User](c.ctx, c.tx, c.account, kUser)
	if err != nil {
		return nil, err
	}
	var out []*User
	for _, u := range users {
		if contains(u.Groups, g.ID) {
			out = append(out, u)
		}
	}
	return out, nil
}

func getGroup(c *call) (obj, error) {
	g, err := c.group(c.f.str("GroupName"))
	if err != nil {
		return nil, err
	}
	users, err := c.groupMembers(g)
	if err != nil {
		return nil, err
	}
	users, tail, err := page(c, users, 100)
	if err != nil {
		return nil, err
	}
	m := members{}
	for _, u := range users {
		m = append(m, userXML(u, false))
	}
	return append(obj{{"Group", groupXML(g)}, {"Users", m}}, tail...), nil
}

func listGroups(c *call) (obj, error) {
	groups, err := loadAll[Group](c.ctx, c.tx, c.account, kGroup)
	if err != nil {
		return nil, err
	}
	prefix := c.f.str("PathPrefix")
	var list []*Group
	for _, g := range groups {
		if strings.HasPrefix(g.Path, prefix) {
			list = append(list, g)
		}
	}
	list, tail, err := page(c, list, 100)
	if err != nil {
		return nil, err
	}
	m := members{}
	for _, g := range list {
		m = append(m, groupXML(g))
	}
	return append(obj{{"Groups", m}}, tail...), nil
}

func listGroupsForUser(c *call) (obj, error) {
	u, err := c.user(c.f.str("UserName"))
	if err != nil {
		return nil, err
	}
	groups, err := loadAll[Group](c.ctx, c.tx, c.account, kGroup)
	if err != nil {
		return nil, err
	}
	var list []*Group
	for _, g := range groups {
		if contains(u.Groups, g.ID) {
			list = append(list, g)
		}
	}
	list, tail, err := page(c, list, 100)
	if err != nil {
		return nil, err
	}
	m := members{}
	for _, g := range list {
		m = append(m, groupXML(g))
	}
	return append(obj{{"Groups", m}}, tail...), nil
}

func updateGroup(c *call) (obj, error) {
	name := c.f.str("GroupName")
	var g Group
	ok, err := load(c.ctx, c.tx, c.account, kGroup, nameKey(name), &g)
	if err != nil {
		return nil, err
	}
	newName := c.f.str("NewGroupName")
	if newName != "" && nameKey(newName) != nameKey(name) {
		var other Group
		if taken, err := load(c.ctx, c.tx, c.account, kGroup, nameKey(newName), &other); err != nil {
			return nil, err
		} else if taken {
			return nil, alreadyExists("Group %s already exists", newName)
		}
	}
	if !ok {
		return nil, noSuchEntity("The group with name %s cannot be found.", name)
	}
	if p := c.f.str("NewPath"); p != "" {
		if err := validatePath(p); err != nil {
			return nil, err
		}
		g.Path = p
	}
	if newName != "" {
		g.Name = newName
	}
	g.ARN = c.arn("group" + g.Path + g.Name)
	return nil, rename(c.ctx, c.tx, c.account, kGroup, nameKey(name), nameKey(g.Name), &g)
}

func deleteGroup(c *call) (obj, error) {
	name := c.f.str("GroupName")
	var g Group
	ok, err := load(c.ctx, c.tx, c.account, kGroup, nameKey(name), &g)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, noSuchEntity("The group with name %s cannot be found.", name)
	}
	users, err := c.groupMembers(&g)
	if err != nil {
		return nil, err
	}
	switch {
	case len(users) > 0:
		return nil, deleteConflict("Cannot delete entity, must remove users from group first.")
	case len(g.Attached) > 0:
		return nil, deleteConflict("Cannot delete entity, must detach all policies first.")
	case len(g.Inline) > 0:
		return nil, deleteConflict("Cannot delete entity, must delete policies first.")
	}
	return nil, remove(c.ctx, c.tx, c.account, kGroup, nameKey(g.Name))
}

func addUserToGroup(c *call) (obj, error) {
	u, err := c.user(c.f.str("UserName"))
	if err != nil {
		return nil, err
	}
	g, err := c.group(c.f.str("GroupName"))
	if err != nil {
		return nil, err
	}
	if !contains(u.Groups, g.ID) {
		u.Groups = append(u.Groups, g.ID)
	}
	return nil, c.saveUser(u)
}

func removeUserFromGroup(c *call) (obj, error) {
	g, err := c.group(c.f.str("GroupName"))
	if err != nil {
		return nil, err
	}
	u, err := c.user(c.f.str("UserName"))
	if err != nil {
		return nil, err
	}
	if !contains(u.Groups, g.ID) {
		return nil, noSuchEntity("User %s not in group %s", u.Name, g.Name)
	}
	u.Groups = without(u.Groups, g.ID)
	return nil, c.saveUser(u)
}
