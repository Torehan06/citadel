package iam

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

var tagKeyPattern = regexp.MustCompile(`^[\p{L}\p{Z}\p{N}_.:/=+\-@]+$`)

// readTags parses Tags.member.N.{Key,Value} and validates them as IAM does:
// at most 50, keys unique regardless of case, key ≤ 128 and value ≤ 256
// characters, keys from a restricted character set.
func readTags(f form, param string) ([]Tag, error) {
	var tags []Tag
	for _, m := range f.structs(param) {
		tags = append(tags, Tag{Key: m["Key"], Value: m["Value"]})
	}
	return tags, validateTags(tags)
}

func validateTags(tags []Tag) error {
	if len(tags) > 50 {
		return validationError("1 validation error detected: Value '%s' at 'tags' failed to satisfy constraint: Member must have length less than or equal to 50.", tagsString(tags))
	}
	seen := map[string]bool{}
	for _, t := range tags {
		k := strings.ToLower(t.Key)
		if seen[k] {
			return invalidInput("Duplicate tag keys found. Please note that Tag keys are case insensitive.")
		}
		seen[k] = true
		if err := validateTagKey(t.Key, "tags.X.member.key"); err != nil {
			return err
		}
		if utf8.RuneCountInString(t.Value) > 256 {
			return validationError("1 validation error detected: Value '%s' at 'tags.X.member.value' failed to satisfy constraint: Member must have length less than or equal to 256.", t.Value)
		}
	}
	return nil
}

func validateTagKey(key, param string) error {
	if utf8.RuneCountInString(key) > 128 {
		return validationError("1 validation error detected: Value '%s' at '%s' failed to satisfy constraint: Member must have length less than or equal to 128.", key, param)
	}
	if !tagKeyPattern.MatchString(key) {
		return validationError(`1 validation error detected: Value '%s' at '%s' failed to satisfy constraint: Member must satisfy regular expression pattern: [\p{L}\p{Z}\p{N}_.:/=+\-@]+`, key, param)
	}
	return nil
}

func readTagKeys(f form) ([]string, error) {
	keys := f.list("TagKeys")
	if len(keys) > 50 {
		return nil, validationError("1 validation error detected: Value '%v' at 'tagKeys' failed to satisfy constraint: Member must have length less than or equal to 50.", keys)
	}
	for _, k := range keys {
		if err := validateTagKey(k, "tagKeys"); err != nil {
			return nil, err
		}
	}
	return keys, nil
}

func tagsString(tags []Tag) string {
	parts := make([]string, len(tags))
	for i, t := range tags {
		parts[i] = fmt.Sprintf("{Key: %s, Value: %s}", t.Key, t.Value)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

// mergeTags adds or replaces tags (keys compare without case).
func mergeTags(have, add []Tag) []Tag {
	out := append([]Tag(nil), have...)
	for _, t := range add {
		replaced := false
		for i := range out {
			if strings.EqualFold(out[i].Key, t.Key) {
				out[i] = t
				replaced = true
				break
			}
		}
		if !replaced {
			out = append(out, t)
		}
	}
	return out
}

func removeTags(have []Tag, keys []string) []Tag {
	var out []Tag
	for _, t := range have {
		drop := false
		for _, k := range keys {
			if strings.EqualFold(t.Key, k) {
				drop = true
				break
			}
		}
		if !drop {
			out = append(out, t)
		}
	}
	return out
}

func tagsXML(tags []Tag) members {
	out := make(members, len(tags))
	for i, t := range tags {
		out[i] = obj{{"Key", t.Key}, {"Value", t.Value}}
	}
	return out
}

// page applies Marker/MaxItems pagination (the marker is an offset).
func page[T any](c *call, items []T, def int) ([]T, obj, error) {
	start := 0
	if m := c.f.str("Marker"); m != "" {
		if _, err := fmt.Sscanf(m, "%d", &start); err != nil || start < 0 {
			return nil, nil, validationError("Invalid Marker.")
		}
	}
	max, err := c.f.intValue("MaxItems", def)
	if err != nil {
		return nil, nil, err
	}
	if max <= 0 {
		max = def
	}
	if start > len(items) {
		start = len(items)
	}
	end := start + max
	truncated := end < len(items)
	if !truncated {
		end = len(items)
	}
	tail := obj{{"IsTruncated", truncated}}
	if truncated {
		tail = append(tail, kv{"Marker", fmt.Sprint(end)})
	}
	return items[start:end], tail, nil
}
