package lambda

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"citadel/internal/store"
)

var randRead = rand.Read

type routingConfig struct {
	AdditionalVersionWeights map[string]float64 `json:"AdditionalVersionWeights"`
}

type aliasConfig struct {
	AliasArn        string         `json:"AliasArn"`
	Name            string         `json:"Name"`
	FunctionVersion string         `json:"FunctionVersion"`
	Description     string         `json:"Description"`
	RevisionId      string         `json:"RevisionId"`
	RoutingConfig   *routingConfig `json:"RoutingConfig,omitempty"`
}

func loadAlias(ctx context.Context, q querier, fid int64, name string) (*aliasConfig, error) {
	var cfg string
	err := q.QueryRowContext(ctx, `SELECT config FROM lambda_aliases WHERE function_id=? AND name=?`, fid, name).Scan(&cfg)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var a aliasConfig
	return &a, json.Unmarshal([]byte(cfg), &a)
}

func saveAlias(ctx context.Context, tx *store.Tx, fid int64, a *aliasConfig) error {
	b, _ := json.Marshal(a)
	_, err := tx.ExecContext(ctx, `INSERT INTO lambda_aliases(function_id, name, config) VALUES (?,?,?)
		ON CONFLICT(function_id, name) DO UPDATE SET config=excluded.config`, fid, a.Name, string(b))
	return err
}

type aliasRequest struct {
	Name            string
	FunctionVersion *string
	Description     *string
	RoutingConfig   *routingConfig
	RevisionId      string
}

// checkTarget verifies that the version an alias points at (and the versions
// it routes extra traffic to) exist.
func (c *call) checkTarget(q querier, fn *function, r *aliasRequest) error {
	versions := []string{}
	if r.FunctionVersion != nil {
		versions = append(versions, *r.FunctionVersion)
	}
	if r.RoutingConfig != nil {
		for v, w := range r.RoutingConfig.AdditionalVersionWeights {
			if w < 0 || w > 1 {
				return validation(strconv.FormatFloat(w, 'f', -1, 64), "routingConfig.additionalVersionWeights", "Map value must satisfy constraint: [Member must have value less than or equal to 1.0, Member must have value greater than or equal to 0.0]")
			}
			versions = append(versions, v)
		}
	}
	for _, v := range versions {
		n := 0
		if v != latest {
			if !isDigits(v) {
				return validation(v, "functionVersion", `Member must satisfy regular expression pattern: (\$LATEST|[0-9]+)`)
			}
			n, _ = strconv.Atoi(v)
		}
		got, err := loadVersion(c.ctx, q, fn.ID, n)
		if err != nil {
			return err
		}
		if got == nil || (n == 0 && v != latest) {
			return notFound("Function not found: %s:%s", c.functionARN(fn.Name), v)
		}
	}
	return nil
}

func (h *Handler) createAlias(c *call, raw string) error {
	f, err := parseRef(raw)
	if err != nil {
		return err
	}
	if err := h.authorize(c, "CreateAlias", c.functionARN(f.name)); err != nil {
		return err
	}
	var req aliasRequest
	if err := c.decode(&req, 1<<20); err != nil {
		return err
	}
	if len(req.Name) == 0 || len(req.Name) > 128 || !aliasNameRE.MatchString(req.Name) {
		return validation(req.Name, "name", `Member must satisfy regular expression pattern: (?!^[0-9]+$)([a-zA-Z0-9-_]+)`)
	}
	if req.FunctionVersion == nil {
		return validation("null", "functionVersion", "Member must not be null")
	}
	f.qualifier = ""
	var out *aliasConfig
	err = h.st.Update(c.ctx, func(tx *store.Tx) error {
		fn, err := c.loadFunction(tx, f)
		if err != nil {
			return err
		}
		if err := c.checkTarget(tx, fn, &req); err != nil {
			return err
		}
		existing, err := loadAlias(c.ctx, tx, fn.ID, req.Name)
		if err != nil {
			return err
		}
		arn := c.functionARN(fn.Name) + ":" + req.Name
		if existing != nil {
			return conflict("Alias already exists: %s", arn)
		}
		out = &aliasConfig{AliasArn: arn, Name: req.Name, FunctionVersion: *req.FunctionVersion, RevisionId: newRevision(), RoutingConfig: req.RoutingConfig}
		if req.Description != nil {
			out.Description = *req.Description
		}
		if err := saveAlias(c.ctx, tx, fn.ID, out); err != nil {
			return err
		}
		return tx.Change("lambda", "CreateAlias", arn, map[string]string{"version": out.FunctionVersion})
	})
	if err != nil {
		return err
	}
	writeJSON(c.w, 201, out)
	return nil
}

func (h *Handler) alias(c *call, raw, name string) error {
	f, err := parseRef(raw)
	if err != nil {
		return err
	}
	f.qualifier = ""
	arn := c.functionARN(f.name) + ":" + name
	switch c.r.Method {
	case http.MethodGet:
		if err := h.authorize(c, "GetAlias", c.functionARN(f.name)); err != nil {
			return err
		}
		fn, err := c.loadFunction(h.st.DB(), f)
		if err != nil {
			return err
		}
		a, err := loadAlias(c.ctx, h.st.DB(), fn.ID, name)
		if err != nil {
			return err
		}
		if a == nil {
			return notFound("Cannot find alias arn: %s", arn)
		}
		writeJSON(c.w, 200, a)
		return nil
	case http.MethodPut:
		if err := h.authorize(c, "UpdateAlias", c.functionARN(f.name)); err != nil {
			return err
		}
		var req aliasRequest
		if err := c.decode(&req, 1<<20); err != nil {
			return err
		}
		var out *aliasConfig
		err := h.st.Update(c.ctx, func(tx *store.Tx) error {
			fn, err := c.loadFunction(tx, f)
			if err != nil {
				return err
			}
			a, err := loadAlias(c.ctx, tx, fn.ID, name)
			if err != nil {
				return err
			}
			if a == nil {
				return notFound("Cannot find alias arn: %s", arn)
			}
			if req.RevisionId != "" && req.RevisionId != a.RevisionId {
				return errorf(412, "PreconditionFailedException", "The Revision Id provided does not match the latest Revision Id. Call the GetFunction/GetAlias API to retrieve the latest Revision Id")
			}
			if err := c.checkTarget(tx, fn, &req); err != nil {
				return err
			}
			if req.FunctionVersion != nil {
				a.FunctionVersion = *req.FunctionVersion
			}
			if req.Description != nil {
				a.Description = *req.Description
			}
			if req.RoutingConfig != nil {
				a.RoutingConfig = req.RoutingConfig
				if len(req.RoutingConfig.AdditionalVersionWeights) == 0 {
					a.RoutingConfig = nil
				}
			}
			a.RevisionId = newRevision()
			out = a
			if err := saveAlias(c.ctx, tx, fn.ID, a); err != nil {
				return err
			}
			return tx.Change("lambda", "UpdateAlias", arn, map[string]string{"version": a.FunctionVersion})
		})
		if err != nil {
			return err
		}
		writeJSON(c.w, 200, out)
		return nil
	case http.MethodDelete:
		if err := h.authorize(c, "DeleteAlias", c.functionARN(f.name)); err != nil {
			return err
		}
		err := h.st.Update(c.ctx, func(tx *store.Tx) error {
			fn, err := c.loadFunction(tx, f)
			if err != nil {
				return err
			}
			res, err := tx.ExecContext(c.ctx, `DELETE FROM lambda_aliases WHERE function_id=? AND name=?`, fn.ID, name)
			if err != nil {
				return err
			}
			if n, _ := res.RowsAffected(); n == 0 {
				return notFound("Cannot find alias arn: %s", arn)
			}
			if _, err := tx.ExecContext(c.ctx, `DELETE FROM lambda_settings WHERE function_id=? AND qualifier=?`, fn.ID, name); err != nil {
				return err
			}
			return tx.Change("lambda", "DeleteAlias", arn, nil)
		})
		if err != nil {
			return err
		}
		writeJSON(c.w, 204, nil)
		return nil
	}
	return errorf(501, "NotImplemented", "citadel: Lambda %s %s is not implemented yet", c.r.Method, c.r.URL.Path)
}

func (h *Handler) listAliases(c *call, raw string) error {
	f, err := parseRef(raw)
	if err != nil {
		return err
	}
	if err := h.authorize(c, "ListAliases", c.functionARN(f.name)); err != nil {
		return err
	}
	f.qualifier = ""
	fn, err := c.loadFunction(h.st.DB(), f)
	if err != nil {
		return err
	}
	offset, limit, err := marker(c)
	if err != nil {
		return err
	}
	q := `SELECT config FROM lambda_aliases WHERE function_id=?`
	args := []any{fn.ID}
	if v := c.query("FunctionVersion"); v != "" {
		q += ` AND json_extract(config, '$.FunctionVersion') = ?`
		args = append(args, v)
	}
	q += ` ORDER BY name LIMIT ? OFFSET ?`
	args = append(args, limit+1, offset)
	rows, err := h.st.DB().QueryContext(c.ctx, q, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	list := []aliasConfig{}
	for rows.Next() {
		var cfg string
		var a aliasConfig
		if err := rows.Scan(&cfg); err != nil {
			return err
		}
		if err := json.Unmarshal([]byte(cfg), &a); err != nil {
			return err
		}
		list = append(list, a)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	out := map[string]any{"Aliases": list}
	if len(list) > limit {
		out["Aliases"] = list[:limit]
		out["NextMarker"] = strconv.Itoa(offset + limit)
	}
	writeJSON(c.w, 200, out)
	return nil
}
