package lambda

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"

	"citadel/internal/store"
)

func init() {
	handle("POST", "/2015-03-31/functions/{FunctionName}/aliases", "CreateAlias", (*Handler).createAlias)
	handle("GET", "/2015-03-31/functions/{FunctionName}/aliases", "ListAliases", (*Handler).listAliases)
	handle("GET", "/2015-03-31/functions/{FunctionName}/aliases/{Name}", "GetAlias", (*Handler).getAlias)
	handle("PUT", "/2015-03-31/functions/{FunctionName}/aliases/{Name}", "UpdateAlias", (*Handler).updateAlias)
	handle("DELETE", "/2015-03-31/functions/{FunctionName}/aliases/{Name}", "DeleteAlias", (*Handler).deleteAlias)
}

// alias is an AliasConfiguration.
type alias struct {
	AliasArn        string         `json:"AliasArn"`
	Name            string         `json:"Name"`
	FunctionVersion string         `json:"FunctionVersion"`
	Description     string         `json:"Description"`
	RoutingConfig   map[string]any `json:"RoutingConfig,omitempty"`
	RevisionId      string         `json:"RevisionId"`
}

var aliasPattern = regexp.MustCompile(`^[a-zA-Z0-9-_]{1,128}$`)

func validAliasName(n string) bool {
	if !aliasPattern.MatchString(n) {
		return false
	}
	_, numeric := versionNumber(n)
	return !numeric && n != "$LATEST"
}

func loadAlias(ctx context.Context, q querier, ref fnRef, name string) (*alias, error) {
	var doc string
	err := q.QueryRowContext(ctx, `SELECT doc FROM lambda_aliases WHERE account_id=? AND region=? AND name=? AND alias=?`,
		ref.account, ref.region, ref.name, name).Scan(&doc)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var a alias
	return &a, json.Unmarshal([]byte(doc), &a)
}

func listAliases(ctx context.Context, q querier, ref fnRef) ([]*alias, error) {
	rows, err := q.QueryContext(ctx, `SELECT doc FROM lambda_aliases WHERE account_id=? AND region=? AND name=? ORDER BY alias`,
		ref.account, ref.region, ref.name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*alias
	for rows.Next() {
		var doc string
		if err := rows.Scan(&doc); err != nil {
			return nil, err
		}
		var a alias
		if err := json.Unmarshal([]byte(doc), &a); err != nil {
			return nil, err
		}
		out = append(out, &a)
	}
	return out, rows.Err()
}

func saveAlias(ctx context.Context, q querier, ref fnRef, a *alias) error {
	_, err := q.ExecContext(ctx, `INSERT INTO lambda_aliases(account_id, region, name, alias, doc) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(account_id, region, name, alias) DO UPDATE SET doc = excluded.doc`,
		ref.account, ref.region, ref.name, a.Name, jsonString(a))
	return err
}

// checkVersion verifies a version an alias would point at exists.
func checkVersion(ctx context.Context, q querier, ref fnRef, ver string) error {
	num, ok := versionNumber(ver)
	if !ok {
		return constraint(ver, "functionVersion", "Member must satisfy regular expression pattern: (\\$LATEST|[0-9]+)")
	}
	v, err := loadVersion(ctx, q, ref, num)
	if err != nil {
		return err
	}
	if v == nil {
		return functionNotFound(ref, ver)
	}
	return nil
}

func checkRouting(rc map[string]any) error {
	if rc == nil {
		return nil
	}
	weights, _ := rc["AdditionalVersionWeights"].(map[string]any)
	for ver, w := range weights {
		if _, ok := versionNumber(ver); !ok || ver == "$LATEST" {
			return constraint(ver, "routingConfig.additionalVersionWeights.key", "Member must satisfy regular expression pattern: [0-9]+")
		}
		f, _ := w.(float64)
		if f < 0 || f > 1 {
			return constraint(w, "routingConfig.additionalVersionWeights.value", "Member must have value less than or equal to 1.0")
		}
	}
	return nil
}

func (h *Handler) createAlias(c *call) (*result, error) {
	ref, err := c.parseName(c.params["FunctionName"], "")
	if err != nil {
		return nil, err
	}
	if err := h.authorize(c, "CreateAlias", ref.arn()); err != nil {
		return nil, err
	}
	var in struct {
		Name, FunctionVersion, Description string
		RoutingConfig                      map[string]any
	}
	if err := c.decode(&in); err != nil {
		return nil, err
	}
	if !validAliasName(in.Name) {
		return nil, constraint(in.Name, "name", "Member must satisfy regular expression pattern: (?!^[0-9]+$)([a-zA-Z0-9-_]+)")
	}
	if err := checkRouting(in.RoutingConfig); err != nil {
		return nil, err
	}
	a := &alias{
		AliasArn: ref.qualifiedARN(in.Name), Name: in.Name, FunctionVersion: in.FunctionVersion,
		Description: in.Description, RoutingConfig: in.RoutingConfig, RevisionId: newUUID(),
	}
	err = h.st.Update(c.ctx, func(tx *store.Tx) error {
		if _, err := mustFunction(c.ctx, tx, ref); err != nil {
			return err
		}
		if err := checkVersion(c.ctx, tx, ref, in.FunctionVersion); err != nil {
			return err
		}
		existing, err := loadAlias(c.ctx, tx, ref, in.Name)
		if err != nil {
			return err
		}
		if existing != nil {
			return conflict("Alias already exists: %s", a.AliasArn)
		}
		if err := saveAlias(c.ctx, tx, ref, a); err != nil {
			return err
		}
		return tx.Change("lambda", "CreateAlias", a.AliasArn, nil)
	})
	if err != nil {
		return nil, err
	}
	return ok(201, a), nil
}

func (h *Handler) listAliases(c *call) (*result, error) {
	ref, err := c.parseName(c.params["FunctionName"], "")
	if err != nil {
		return nil, err
	}
	if err := h.authorize(c, "ListAliases", ref.arn()); err != nil {
		return nil, err
	}
	db := h.st.DB()
	if _, err := mustFunction(c.ctx, db, ref); err != nil {
		return nil, err
	}
	all, err := listAliases(c.ctx, db, ref)
	if err != nil {
		return nil, err
	}
	maxItems, err := intParam(c.query, "MaxItems", 50)
	if err != nil {
		return nil, err
	}
	fv, marker := c.query.Get("FunctionVersion"), c.query.Get("Marker")
	list := []*alias{}
	out := map[string]any{}
	for _, a := range all {
		if (fv != "" && a.FunctionVersion != fv) || (marker != "" && a.Name <= marker) {
			continue
		}
		if len(list) == maxItems {
			out["NextMarker"] = list[len(list)-1].Name
			break
		}
		list = append(list, a)
	}
	out["Aliases"] = list
	return ok(200, out), nil
}

// aliasRef parses the function and alias name path parameters.
func (c *call) aliasRef() (fnRef, string, error) {
	ref, err := c.parseName(c.params["FunctionName"], "")
	return ref, c.params["Name"], err
}

func (h *Handler) getAlias(c *call) (*result, error) {
	ref, name, err := c.aliasRef()
	if err != nil {
		return nil, err
	}
	if err := h.authorize(c, "GetAlias", ref.qualifiedARN(name)); err != nil {
		return nil, err
	}
	a, err := loadAlias(c.ctx, h.st.DB(), ref, name)
	if err != nil {
		return nil, err
	}
	if a == nil {
		return nil, notFound("Cannot find alias arn: %s", ref.qualifiedARN(name))
	}
	return ok(200, a), nil
}

func (h *Handler) updateAlias(c *call) (*result, error) {
	ref, name, err := c.aliasRef()
	if err != nil {
		return nil, err
	}
	if err := h.authorize(c, "UpdateAlias", ref.qualifiedARN(name)); err != nil {
		return nil, err
	}
	var in struct {
		FunctionVersion, Description *string
		RoutingConfig                map[string]any
		RevisionId                   string
	}
	if err := c.decode(&in); err != nil {
		return nil, err
	}
	if err := checkRouting(in.RoutingConfig); err != nil {
		return nil, err
	}
	var a *alias
	err = h.st.Update(c.ctx, func(tx *store.Tx) error {
		var err error
		if a, err = loadAlias(c.ctx, tx, ref, name); err != nil {
			return err
		}
		if a == nil {
			return notFound("Cannot find alias arn: %s", ref.qualifiedARN(name))
		}
		if in.RevisionId != "" && in.RevisionId != a.RevisionId {
			return errf(412, "PreconditionFailedException", "The Revision Id provided does not match the latest Revision Id. Call the GetFunction/GetAlias API to retrieve the latest Revision Id")
		}
		if in.FunctionVersion != nil {
			if err := checkVersion(c.ctx, tx, ref, *in.FunctionVersion); err != nil {
				return err
			}
			a.FunctionVersion = *in.FunctionVersion
		}
		if in.Description != nil {
			a.Description = *in.Description
		}
		if in.RoutingConfig != nil {
			a.RoutingConfig = in.RoutingConfig
			if w, _ := in.RoutingConfig["AdditionalVersionWeights"].(map[string]any); len(w) == 0 {
				a.RoutingConfig = nil
			}
		}
		a.RevisionId = newUUID()
		if err := saveAlias(c.ctx, tx, ref, a); err != nil {
			return err
		}
		return tx.Change("lambda", "UpdateAlias", a.AliasArn, nil)
	})
	if err != nil {
		return nil, err
	}
	return ok(200, a), nil
}

func (h *Handler) deleteAlias(c *call) (*result, error) {
	ref, name, err := c.aliasRef()
	if err != nil {
		return nil, err
	}
	if err := h.authorize(c, "DeleteAlias", ref.qualifiedARN(name)); err != nil {
		return nil, err
	}
	err = h.st.Update(c.ctx, func(tx *store.Tx) error {
		if _, err := mustFunction(c.ctx, tx, ref); err != nil {
			return err
		}
		if _, err := tx.ExecContext(c.ctx, `DELETE FROM lambda_aliases WHERE account_id=? AND region=? AND name=? AND alias=?`,
			ref.account, ref.region, ref.name, name); err != nil {
			return err
		}
		return tx.Change("lambda", "DeleteAlias", ref.qualifiedARN(name), nil)
	})
	if err != nil {
		return nil, err
	}
	return ok(http.StatusNoContent, nil), nil
}
