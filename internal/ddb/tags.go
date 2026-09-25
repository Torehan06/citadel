package ddb

import (
	"strings"
	"unicode/utf8"

	"citadel/internal/store"
)

// Resource tags: TagResource, UntagResource, ListTagsOfResource.
// https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Tagging.html

func init() {
	register("TagResource", (*Handler).tagResource)
	register("UntagResource", (*Handler).untagResource)
	register("ListTagsOfResource", (*Handler).listTags)
}

const maxTags = 50

func validateTags(tags []tagKV) error {
	for _, t := range tags {
		if t.Key == "" || utf8.RuneCountInString(t.Key) > 128 {
			return validation("1 validation error detected: Value '%s' at 'tags.member.key' failed to satisfy constraint: Member must have length less than or equal to 128 and greater than or equal to 1", t.Key)
		}
		if utf8.RuneCountInString(t.Value) > 256 {
			return validation("1 validation error detected: Value '%s' at 'tags.member.value' failed to satisfy constraint: Member must have length less than or equal to 256", t.Value)
		}
		if strings.HasPrefix(t.Key, "aws:") {
			return validation("One or more parameter values were invalid: Tag key cannot start with the reserved prefix aws:")
		}
	}
	if len(tags) > maxTags {
		return validation("One or more parameter values were invalid: The number of tags exceeds the limit of %d", maxTags)
	}
	return nil
}

// tableByARN resolves a table ARN in the caller's account and this region.
func (h *Handler) tableByARN(c *call, arn string) (*table, error) {
	if arn == "" {
		return nil, validation("1 validation error detected: Value null at 'resourceArn' failed to satisfy constraint: Member must not be null")
	}
	prefix := "arn:aws:dynamodb:" + h.region + ":" + c.account + ":table/"
	name, ok := strings.CutPrefix(arn, prefix)
	if !ok || name == "" || strings.Contains(name, "/") {
		if strings.HasPrefix(arn, "arn:") {
			return nil, notFound("Requested resource not found: ResourcArn: %s not found", arn)
		}
		return nil, errf(400, "ValidationException", "Invalid TableArn: Invalid ResourceArn provided as input %s", arn)
	}
	t, err := h.loadTable(c, name)
	if err != nil {
		if e, ok := err.(*Error); ok && e.Code == "ResourceNotFoundException" {
			return nil, notFound("Requested resource not found: ResourcArn: %s not found", arn)
		}
		return nil, err
	}
	return t, nil
}

type tagInput struct {
	ResourceArn string   `json:"ResourceArn"`
	Tags        []tagKV  `json:"Tags"`
	TagKeys     []string `json:"TagKeys"`
	NextToken   string   `json:"NextToken"`
}

func (h *Handler) tagResource(c *call) (any, error) {
	var in tagInput
	if err := decode(c, &in); err != nil {
		return nil, err
	}
	if in.Tags == nil {
		return nil, validation("1 validation error detected: Value null at 'tags' failed to satisfy constraint: Member must not be null")
	}
	if err := validateTags(in.Tags); err != nil {
		return nil, err
	}
	return map[string]any{}, h.st.Update(c.ctx, func(tx *store.Tx) error {
		t, err := h.tableByARN(c, in.ResourceArn)
		if err != nil {
			return err
		}
		for _, nt := range in.Tags {
			replaced := false
			for i := range t.desc.Tags {
				if t.desc.Tags[i].Key == nt.Key {
					t.desc.Tags[i].Value, replaced = nt.Value, true
				}
			}
			if !replaced {
				t.desc.Tags = append(t.desc.Tags, nt)
			}
		}
		if err := validateTags(t.desc.Tags); err != nil {
			return err
		}
		if err := saveDesc(c, tx, t); err != nil {
			return err
		}
		return tx.Change("dynamodb", "TagResource", t.desc.TableName, nil)
	})
}

func (h *Handler) untagResource(c *call) (any, error) {
	var in tagInput
	if err := decode(c, &in); err != nil {
		return nil, err
	}
	if in.TagKeys == nil {
		return nil, validation("1 validation error detected: Value null at 'tagKeys' failed to satisfy constraint: Member must not be null")
	}
	return map[string]any{}, h.st.Update(c.ctx, func(tx *store.Tx) error {
		t, err := h.tableByARN(c, in.ResourceArn)
		if err != nil {
			return err
		}
		drop := map[string]bool{}
		for _, k := range in.TagKeys {
			drop[k] = true
		}
		var keep []tagKV
		for _, tg := range t.desc.Tags {
			if !drop[tg.Key] {
				keep = append(keep, tg)
			}
		}
		t.desc.Tags = keep
		if err := saveDesc(c, tx, t); err != nil {
			return err
		}
		return tx.Change("dynamodb", "UntagResource", t.desc.TableName, nil)
	})
}

func (h *Handler) listTags(c *call) (any, error) {
	var in tagInput
	if err := decode(c, &in); err != nil {
		return nil, err
	}
	t, err := h.tableByARN(c, in.ResourceArn)
	if err != nil {
		return nil, err
	}
	tags := t.desc.Tags
	if tags == nil {
		tags = []tagKV{}
	}
	return map[string]any{"Tags": tags}, nil
}
