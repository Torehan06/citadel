// Package logs implements the slice of CloudWatch Logs that reading Lambda
// function logs needs: log groups and streams, PutLogEvents, GetLogEvents and
// FilterLogEvents over the AWS JSON 1.1 protocol. Lambda writes through
// Append, in-process.
package logs

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"citadel/internal/iam"
	"citadel/internal/sigv4"
	"citadel/internal/store"
)

type Handler struct {
	st     *store.Store
	auth   *sigv4.Verifier
	region string
	log    *slog.Logger
	now    func() time.Time
	// IAM enforces identity policies for IAM users and role sessions.
	IAM *iam.Authorizer
}

func New(st *store.Store, auth *sigv4.Verifier, region string, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{st: st, auth: auth, region: region, log: logger, now: time.Now}
}

type serviceError struct {
	Status        int
	Code, Message string
}

func (e *serviceError) Error() string { return e.Code + ": " + e.Message }

func fail(code, format string, args ...any) error {
	return &serviceError{400, code, fmt.Sprintf(format, args...)}
}

func missingGroup() error {
	return fail("ResourceNotFoundException", "The specified log group does not exist.")
}

func missingStream() error {
	return fail("ResourceNotFoundException", "The specified log stream does not exist.")
}

type request struct {
	LogGroupName, LogGroupNamePrefix, LogGroupIdentifier string
	LogStreamName, LogStreamNamePrefix                   string
	LogStreamNames                                       []string
	OrderBy                                              string
	Descending                                           bool
	NextToken                                            *string
	Limit                                                *int
	StartTime, EndTime                                   *int64
	StartFromHead                                        *bool
	FilterPattern                                        string
	LogEvents                                            []Event
	RetentionInDays                                      *int
	Tags                                                 map[string]string
}

// Event is one log line. Timestamps are unix milliseconds.
type Event struct {
	Timestamp int64  `json:"timestamp"`
	Message   string `json:"message"`
}

type call struct {
	ctx             context.Context
	account, region string
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	op := r.Header.Get("X-Amz-Target")
	op = op[strings.IndexByte(op, '.')+1:]
	out, err := h.serve(r, op)
	if err != nil {
		var e *serviceError
		if !errors.As(err, &e) {
			var se *sigv4.Error
			if errors.As(err, &se) {
				e = &serviceError{403, se.Code, se.Message}
			} else {
				h.log.Error("logs internal error", "op", op, "err", err)
				e = &serviceError{500, "ServiceUnavailableException", "Internal server error"}
			}
		}
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		w.Header().Set("x-amzn-ErrorType", e.Code)
		w.WriteHeader(e.Status)
		_ = json.NewEncoder(w).Encode(map[string]string{"__type": e.Code, "message": e.Message})
		return
	}
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	_ = json.NewEncoder(w).Encode(out)
}

func (h *Handler) serve(r *http.Request, op string) (map[string]any, error) {
	auth, err := h.auth.Verify(r)
	if err != nil {
		return nil, err
	}
	if auth.Anonymous {
		return nil, &serviceError{403, "MissingAuthenticationTokenException", "Request must be signed."}
	}
	_, who, err := h.st.LookupKey(r.Context(), auth.AccessKey)
	if err != nil {
		return nil, &serviceError{403, "UnrecognizedClientException", "The security token included in the request is invalid."}
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 2<<20))
	if err != nil {
		return nil, err
	}
	var req request
	if len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			return nil, fail("SerializationException", "Invalid request: %v", err)
		}
	}
	if req.LogGroupName == "" && req.LogGroupIdentifier != "" {
		req.LogGroupName = req.LogGroupIdentifier[strings.LastIndexByte(req.LogGroupIdentifier, ':')+1:]
	}
	c := &call{ctx: r.Context(), account: who.Account.ID, region: auth.Region}
	if c.region == "" {
		c.region = h.region
	}
	if h.IAM != nil && !iam.IsRoot(&who) {
		resource := "*"
		if req.LogGroupName != "" {
			resource = "arn:aws:logs:" + c.region + ":" + c.account + ":log-group:" + req.LogGroupName
			if req.LogStreamName != "" {
				resource += ":log-stream:" + req.LogStreamName
			} else {
				resource += ":*"
			}
		}
		d, err := h.IAM.Require(c.ctx, &who, "logs:"+op, []string{resource}, nil)
		if err != nil {
			return nil, err
		}
		if d != nil {
			return nil, &serviceError{400, "AccessDeniedException", iam.DeniedMessage(&who, d.Action, d.Resource, d.Explicit)}
		}
	}
	switch op {
	case "CreateLogGroup":
		return h.createGroup(c, &req)
	case "DeleteLogGroup":
		return h.deleteGroup(c, &req)
	case "DescribeLogGroups":
		return h.describeGroups(c, &req)
	case "PutRetentionPolicy", "DeleteRetentionPolicy":
		return h.retention(c, &req, op == "PutRetentionPolicy")
	case "CreateLogStream":
		return h.createStream(c, &req)
	case "DeleteLogStream":
		return h.deleteStream(c, &req)
	case "DescribeLogStreams":
		return h.describeStreams(c, &req)
	case "PutLogEvents":
		return h.putEvents(c, &req)
	case "GetLogEvents":
		return h.getEvents(c, &req)
	case "FilterLogEvents":
		return h.filterEvents(c, &req)
	default:
		return nil, &serviceError{501, "NotImplemented", "citadel: CloudWatch Logs " + op + " is not implemented yet"}
	}
}

// Reset wipes every log group (moto's /moto-api/reset).
func (h *Handler) Reset() {
	err := h.st.Update(context.Background(), func(tx *store.Tx) error {
		if _, err := tx.Exec(`DELETE FROM logs_groups`); err != nil {
			return err
		}
		return tx.Change("logs", "Reset", "", nil)
	})
	if err != nil {
		h.log.Error("reset logs", "err", err)
	}
}

var groupNameRE = regexp.MustCompile(`^[\.\-_/#A-Za-z0-9]{1,512}$`)

func (c *call) groupARN(name string) string {
	return "arn:aws:logs:" + c.region + ":" + c.account + ":log-group:" + name
}

type querier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func groupID(q querier, c *call, name string) (int64, error) {
	var id int64
	err := q.QueryRowContext(c.ctx, `SELECT id FROM logs_groups WHERE account=? AND region=? AND name=?`, c.account, c.region, name).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, missingGroup()
	}
	return id, err
}

func streamID(q querier, c *call, group, stream string) (int64, error) {
	gid, err := groupID(q, c, group)
	if err != nil {
		return 0, err
	}
	var id int64
	err = q.QueryRowContext(c.ctx, `SELECT id FROM logs_streams WHERE group_id=? AND name=?`, gid, stream).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, missingStream()
	}
	return id, err
}

func (h *Handler) createGroup(c *call, r *request) (map[string]any, error) {
	if !groupNameRE.MatchString(r.LogGroupName) {
		return nil, fail("InvalidParameterException", "1 validation error detected: Value '%s' at 'logGroupName' failed to satisfy constraint: Member must satisfy regular expression pattern: [\\.\\-_/#A-Za-z0-9]+", r.LogGroupName)
	}
	tags := r.Tags
	if tags == nil {
		tags = map[string]string{}
	}
	err := h.st.Update(c.ctx, func(tx *store.Tx) error {
		if _, err := groupID(tx, c, r.LogGroupName); err == nil {
			return fail("ResourceAlreadyExistsException", "The specified log group already exists")
		}
		b, _ := json.Marshal(tags)
		if _, err := tx.ExecContext(c.ctx, `INSERT INTO logs_groups(account, region, name, created, tags) VALUES (?,?,?,?,?)`,
			c.account, c.region, r.LogGroupName, h.now().UnixMilli(), string(b)); err != nil {
			return err
		}
		return tx.Change("logs", "CreateLogGroup", c.groupARN(r.LogGroupName), nil)
	})
	return map[string]any{}, err
}

func (h *Handler) deleteGroup(c *call, r *request) (map[string]any, error) {
	err := h.st.Update(c.ctx, func(tx *store.Tx) error {
		id, err := groupID(tx, c, r.LogGroupName)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(c.ctx, `DELETE FROM logs_groups WHERE id=?`, id); err != nil {
			return err
		}
		return tx.Change("logs", "DeleteLogGroup", c.groupARN(r.LogGroupName), nil)
	})
	return map[string]any{}, err
}

func (h *Handler) retention(c *call, r *request, put bool) (map[string]any, error) {
	var days any
	if put {
		if r.RetentionInDays == nil || !validRetention(*r.RetentionInDays) {
			return nil, fail("InvalidParameterException", "1 validation error detected: Value at 'retentionInDays' failed to satisfy constraint: Member must satisfy enum value set: [1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653]")
		}
		days = *r.RetentionInDays
	}
	err := h.st.Update(c.ctx, func(tx *store.Tx) error {
		id, err := groupID(tx, c, r.LogGroupName)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(c.ctx, `UPDATE logs_groups SET retention=? WHERE id=?`, days, id); err != nil {
			return err
		}
		return tx.Change("logs", "PutRetentionPolicy", c.groupARN(r.LogGroupName), map[string]any{"days": days})
	})
	return map[string]any{}, err
}

func validRetention(d int) bool {
	for _, v := range []int{1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653} {
		if d == v {
			return true
		}
	}
	return false
}

// page applies a numeric NextToken (an offset) and a limit to a result count.
func page(r *request, def, max int) (offset, limit int, err error) {
	limit = def
	if r.Limit != nil {
		if *r.Limit < 1 || *r.Limit > max {
			return 0, 0, fail("InvalidParameterException", "1 validation error detected: Value '%d' at 'limit' failed to satisfy constraint: Member must have value less than or equal to %d", *r.Limit, max)
		}
		limit = *r.Limit
	}
	if r.NextToken != nil {
		if offset, err = strconv.Atoi(*r.NextToken); err != nil || offset < 0 {
			return 0, 0, fail("InvalidParameterException", "The specified nextToken is invalid.")
		}
	}
	return offset, limit, nil
}

func (h *Handler) describeGroups(c *call, r *request) (map[string]any, error) {
	offset, limit, err := page(r, 50, 50)
	if err != nil {
		return nil, err
	}
	rows, err := h.st.DB().QueryContext(c.ctx, `SELECT g.name, g.created, g.retention,
		(SELECT COALESCE(SUM(s.stored_bytes), 0) FROM logs_streams s WHERE s.group_id = g.id)
		FROM logs_groups g WHERE account=? AND region=? AND substr(name, 1, length(?)) = ? ORDER BY name LIMIT ? OFFSET ?`,
		c.account, c.region, r.LogGroupNamePrefix, r.LogGroupNamePrefix, limit+1, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	groups := []map[string]any{}
	for rows.Next() {
		var name string
		var created, stored int64
		var retention sql.NullInt64
		if err := rows.Scan(&name, &created, &retention, &stored); err != nil {
			return nil, err
		}
		g := map[string]any{"logGroupName": name, "creationTime": created, "arn": c.groupARN(name) + ":*",
			"logGroupArn": c.groupARN(name), "storedBytes": stored, "metricFilterCount": 0, "logGroupClass": "STANDARD"}
		if retention.Valid {
			g["retentionInDays"] = retention.Int64
		}
		groups = append(groups, g)
	}
	out := map[string]any{"logGroups": groups}
	if len(groups) > limit {
		out["logGroups"] = groups[:limit]
		out["nextToken"] = strconv.Itoa(offset + limit)
	}
	return out, rows.Err()
}

var streamNameRE = regexp.MustCompile(`^[^:*]{1,512}$`)

func (h *Handler) createStream(c *call, r *request) (map[string]any, error) {
	if !streamNameRE.MatchString(r.LogStreamName) {
		return nil, fail("InvalidParameterException", "1 validation error detected: Value '%s' at 'logStreamName' failed to satisfy constraint: Member must satisfy regular expression pattern: [^:*]*", r.LogStreamName)
	}
	err := h.st.Update(c.ctx, func(tx *store.Tx) error {
		gid, err := groupID(tx, c, r.LogGroupName)
		if err != nil {
			return err
		}
		res, err := tx.ExecContext(c.ctx, `INSERT INTO logs_streams(group_id, name, created) VALUES (?,?,?) ON CONFLICT DO NOTHING`,
			gid, r.LogStreamName, h.now().UnixMilli())
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return fail("ResourceAlreadyExistsException", "The specified log stream already exists")
		}
		return tx.Change("logs", "CreateLogStream", c.groupARN(r.LogGroupName)+":log-stream:"+r.LogStreamName, nil)
	})
	return map[string]any{}, err
}

func (h *Handler) deleteStream(c *call, r *request) (map[string]any, error) {
	err := h.st.Update(c.ctx, func(tx *store.Tx) error {
		id, err := streamID(tx, c, r.LogGroupName, r.LogStreamName)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(c.ctx, `DELETE FROM logs_streams WHERE id=?`, id); err != nil {
			return err
		}
		return tx.Change("logs", "DeleteLogStream", c.groupARN(r.LogGroupName)+":log-stream:"+r.LogStreamName, nil)
	})
	return map[string]any{}, err
}

func (h *Handler) describeStreams(c *call, r *request) (map[string]any, error) {
	if r.OrderBy != "" && r.OrderBy != "LogStreamName" && r.OrderBy != "LastEventTime" {
		return nil, fail("InvalidParameterException", "1 validation error detected: Value '%s' at 'orderBy' failed to satisfy constraint: Member must satisfy enum value set: [LogStreamName, LastEventTime]", r.OrderBy)
	}
	if r.OrderBy == "LastEventTime" && r.LogStreamNamePrefix != "" {
		return nil, fail("InvalidParameterException", "Cannot order by LastEventTime with a logStreamNamePrefix.")
	}
	offset, limit, err := page(r, 50, 50)
	if err != nil {
		return nil, err
	}
	gid, err := groupID(h.st.DB(), c, r.LogGroupName)
	if err != nil {
		return nil, err
	}
	order := "name"
	if r.OrderBy == "LastEventTime" {
		order = "last_event"
	}
	if r.Descending {
		order += " DESC"
	}
	rows, err := h.st.DB().QueryContext(c.ctx, `SELECT name, created, first_event, last_event, last_ingestion, stored_bytes
		FROM logs_streams WHERE group_id=? AND substr(name, 1, length(?)) = ? ORDER BY `+order+`, id LIMIT ? OFFSET ?`,
		gid, r.LogStreamNamePrefix, r.LogStreamNamePrefix, limit+1, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	streams := []map[string]any{}
	for rows.Next() {
		var name string
		var created, first, last, ingest, stored int64
		if err := rows.Scan(&name, &created, &first, &last, &ingest, &stored); err != nil {
			return nil, err
		}
		s := map[string]any{"logStreamName": name, "creationTime": created, "storedBytes": stored,
			"arn": c.groupARN(r.LogGroupName) + ":log-stream:" + name, "uploadSequenceToken": "1"}
		if first > 0 {
			s["firstEventTimestamp"] = first
			s["lastEventTimestamp"] = last
			s["lastIngestionTime"] = ingest
		}
		streams = append(streams, s)
	}
	out := map[string]any{"logStreams": streams}
	if len(streams) > limit {
		out["logStreams"] = streams[:limit]
		out["nextToken"] = strconv.Itoa(offset + limit)
	}
	return out, rows.Err()
}

func (h *Handler) putEvents(c *call, r *request) (map[string]any, error) {
	if len(r.LogEvents) == 0 {
		return nil, fail("InvalidParameterException", "1 validation error detected: Value '[]' at 'logEvents' failed to satisfy constraint: Member must have length greater than or equal to 1")
	}
	if len(r.LogEvents) > 10000 {
		return nil, fail("InvalidParameterException", "1 validation error detected: Value at 'logEvents' failed to satisfy constraint: Member must have length less than or equal to 10000")
	}
	for i := 1; i < len(r.LogEvents); i++ {
		if r.LogEvents[i].Timestamp < r.LogEvents[i-1].Timestamp {
			return nil, fail("InvalidParameterException", "Log events in a single PutLogEvents request must be in chronological order.")
		}
	}
	now := h.now()
	var accepted []Event
	rejected := map[string]any{}
	for i, e := range r.LogEvents {
		switch {
		case e.Timestamp > now.Add(2*time.Hour).UnixMilli():
			rejected["tooNewLogEventStartIndex"] = i
		case e.Timestamp < now.Add(-14*24*time.Hour).UnixMilli():
			rejected["tooOldLogEventEndIndex"] = i
		default:
			accepted = append(accepted, e)
		}
	}
	err := h.st.Update(c.ctx, func(tx *store.Tx) error {
		id, err := streamID(tx, c, r.LogGroupName, r.LogStreamName)
		if err != nil {
			return err
		}
		return appendTx(c.ctx, tx, id, accepted, now)
	})
	if err != nil {
		return nil, err
	}
	out := map[string]any{"nextSequenceToken": strconv.FormatInt(now.UnixNano(), 10)}
	if len(rejected) > 0 {
		out["rejectedLogEventsInfo"] = rejected
	}
	return out, nil
}

func appendTx(ctx context.Context, tx *store.Tx, stream int64, events []Event, now time.Time) error {
	if len(events) == 0 {
		return nil
	}
	var bytes int64
	for _, e := range events {
		if _, err := tx.ExecContext(ctx, `INSERT INTO logs_events(stream_id, ts, ingested, message) VALUES (?,?,?,?)`,
			stream, e.Timestamp, now.UnixMilli(), e.Message); err != nil {
			return err
		}
		bytes += int64(len(e.Message)) + 26
	}
	_, err := tx.ExecContext(ctx, `UPDATE logs_streams SET
		first_event = CASE WHEN first_event = 0 OR first_event > ? THEN ? ELSE first_event END,
		last_event = MAX(last_event, ?), last_ingestion = ?, stored_bytes = stored_bytes + ? WHERE id = ?`,
		events[0].Timestamp, events[0].Timestamp, events[len(events)-1].Timestamp, now.UnixMilli(), bytes, stream)
	return err
}

// Append writes events to a stream, creating its group and stream as needed.
// Services that log on a customer's behalf (Lambda) use it.
func (h *Handler) Append(ctx context.Context, account, region, group, stream string, events []Event) error {
	if len(events) == 0 {
		return nil
	}
	c := &call{ctx: ctx, account: account, region: region}
	now := h.now()
	return h.st.Update(ctx, func(tx *store.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO logs_groups(account, region, name, created) VALUES (?,?,?,?) ON CONFLICT DO NOTHING`,
			account, region, group, now.UnixMilli()); err != nil {
			return err
		}
		gid, err := groupID(tx, c, group)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO logs_streams(group_id, name, created) VALUES (?,?,?) ON CONFLICT DO NOTHING`,
			gid, stream, now.UnixMilli()); err != nil {
			return err
		}
		id, err := streamID(tx, c, group, stream)
		if err != nil {
			return err
		}
		return appendTx(ctx, tx, id, events, now)
	})
}

type eventRow struct {
	id, ts, ingested int64
	stream, message  string
}

func (h *Handler) getEvents(c *call, r *request) (map[string]any, error) {
	limit := 10000
	if r.Limit != nil {
		if *r.Limit < 1 || *r.Limit > 10000 {
			return nil, fail("InvalidParameterException", "1 validation error detected: Value '%d' at 'limit' failed to satisfy constraint: Member must have value less than or equal to 10000", *r.Limit)
		}
		limit = *r.Limit
	}
	id, err := streamID(h.st.DB(), c, r.LogGroupName, r.LogStreamName)
	if err != nil {
		return nil, err
	}
	// Tokens are "f/<id>" (forward, events after id) or "b/<id>" (backward,
	// events before id), as CloudWatch's own tokens carry a direction.
	fromHead := r.StartFromHead != nil && *r.StartFromHead
	cursor := int64(-1)
	if r.NextToken != nil {
		dir, n, ok := strings.Cut(*r.NextToken, "/")
		v, err := strconv.ParseInt(n, 10, 64)
		if !ok || err != nil || (dir != "f" && dir != "b") {
			return nil, fail("InvalidParameterException", "The specified nextToken is invalid.")
		}
		fromHead, cursor = dir == "f", v
	}
	where := `stream_id = ?`
	args := []any{id}
	if r.StartTime != nil {
		where += ` AND ts >= ?`
		args = append(args, *r.StartTime)
	}
	if r.EndTime != nil {
		where += ` AND ts < ?`
		args = append(args, *r.EndTime)
	}
	q := `SELECT id, ts, ingested, message FROM logs_events WHERE ` + where
	if fromHead {
		if cursor >= 0 {
			q += ` AND id > ?`
			args = append(args, cursor)
		}
		q += ` ORDER BY id LIMIT ?`
	} else {
		if cursor >= 0 {
			q += ` AND id < ?`
			args = append(args, cursor)
		}
		q += ` ORDER BY id DESC LIMIT ?`
	}
	args = append(args, limit)
	rows, err := h.st.DB().QueryContext(c.ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var got []eventRow
	for rows.Next() {
		var e eventRow
		if err := rows.Scan(&e.id, &e.ts, &e.ingested, &e.message); err != nil {
			return nil, err
		}
		got = append(got, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if !fromHead { // restore chronological order
		for i, j := 0, len(got)-1; i < j; i, j = i+1, j-1 {
			got[i], got[j] = got[j], got[i]
		}
	}
	events := make([]map[string]any, 0, len(got))
	for _, e := range got {
		events = append(events, map[string]any{"timestamp": e.ts, "message": e.message, "ingestionTime": e.ingested})
	}
	// With no events the tokens stay put, so a caller polling for new
	// events sees the same token when it has reached the end.
	fwd, bwd := cursor, cursor
	if len(got) > 0 {
		fwd, bwd = got[len(got)-1].id, got[0].id
	} else if cursor < 0 {
		fwd, bwd = 0, 0
		if !fromHead {
			// Tailing an empty stream: future events come after everything now there.
			_ = h.st.DB().QueryRowContext(c.ctx, `SELECT COALESCE(MAX(id), 0) FROM logs_events`).Scan(&fwd)
		}
	}
	return map[string]any{
		"events":            events,
		"nextForwardToken":  "f/" + strconv.FormatInt(fwd, 10),
		"nextBackwardToken": "b/" + strconv.FormatInt(bwd, 10),
	}, nil
}

func (h *Handler) filterEvents(c *call, r *request) (map[string]any, error) {
	limit := 10000
	if r.Limit != nil {
		if *r.Limit < 1 || *r.Limit > 10000 {
			return nil, fail("InvalidParameterException", "1 validation error detected: Value '%d' at 'limit' failed to satisfy constraint: Member must have value less than or equal to 10000", *r.Limit)
		}
		limit = *r.Limit
	}
	if len(r.LogStreamNames) > 0 && r.LogStreamNamePrefix != "" {
		return nil, fail("InvalidParameterException", "Cannot specify both logStreamNames and logStreamNamePrefix.")
	}
	gid, err := groupID(h.st.DB(), c, r.LogGroupName)
	if err != nil {
		return nil, err
	}
	match, err := compileFilter(r.FilterPattern)
	if err != nil {
		return nil, err
	}
	after := int64(0)
	if r.NextToken != nil {
		if after, err = strconv.ParseInt(*r.NextToken, 10, 64); err != nil {
			return nil, fail("InvalidParameterException", "The specified nextToken is invalid.")
		}
	}
	where := `s.group_id = ? AND e.id > ? AND substr(s.name, 1, length(?)) = ?`
	args := []any{gid, after, r.LogStreamNamePrefix, r.LogStreamNamePrefix}
	if len(r.LogStreamNames) > 0 {
		where += ` AND s.name IN (?` + strings.Repeat(",?", len(r.LogStreamNames)-1) + `)`
		for _, n := range r.LogStreamNames {
			args = append(args, n)
		}
	}
	if r.StartTime != nil {
		where += ` AND e.ts >= ?`
		args = append(args, *r.StartTime)
	}
	if r.EndTime != nil {
		where += ` AND e.ts <= ?`
		args = append(args, *r.EndTime)
	}
	rows, err := h.st.DB().QueryContext(c.ctx, `SELECT e.id, e.ts, e.ingested, s.name, e.message
		FROM logs_events e JOIN logs_streams s ON s.id = e.stream_id WHERE `+where+` ORDER BY e.id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	events := []map[string]any{}
	searched := map[string]bool{}
	var last int64
	more := false
	for rows.Next() {
		var e eventRow
		if err := rows.Scan(&e.id, &e.ts, &e.ingested, &e.stream, &e.message); err != nil {
			return nil, err
		}
		if !match(e.message) {
			continue
		}
		if len(events) == limit {
			more = true
			break
		}
		searched[e.stream] = true
		last = e.id
		events = append(events, map[string]any{"logStreamName": e.stream, "timestamp": e.ts, "message": e.message,
			"ingestionTime": e.ingested, "eventId": strconv.FormatInt(e.id, 10)})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := map[string]any{"events": events, "searchedLogStreams": []any{}}
	if more {
		out["nextToken"] = strconv.FormatInt(last, 10)
	}
	return out, nil
}

// compileFilter supports CloudWatch's text filter patterns: terms that must
// all appear, "quoted phrases", and -term / ?term (exclusion and any-of).
// JSON and space-delimited patterns ({ $.x = 1 }, [a, b]) are not supported.
func compileFilter(p string) (func(string) bool, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		return func(string) bool { return true }, nil
	}
	if strings.HasPrefix(p, "{") || strings.HasPrefix(p, "[") {
		return nil, &serviceError{501, "NotImplemented", "citadel: JSON and space-delimited filter patterns are not implemented yet"}
	}
	var all, none, any []string
	for len(p) > 0 {
		p = strings.TrimLeft(p, " ")
		if p == "" {
			break
		}
		prefix := byte(0)
		if p[0] == '-' || p[0] == '?' {
			prefix, p = p[0], p[1:]
		}
		var term string
		if strings.HasPrefix(p, `"`) {
			end := strings.IndexByte(p[1:], '"')
			if end < 0 {
				return nil, fail("InvalidParameterException", "Invalid filter pattern")
			}
			term, p = p[1:end+1], p[end+2:]
		} else {
			end := strings.IndexByte(p, ' ')
			if end < 0 {
				end = len(p)
			}
			term, p = p[:end], p[end:]
		}
		switch prefix {
		case '-':
			none = append(none, term)
		case '?':
			any = append(any, term)
		default:
			all = append(all, term)
		}
	}
	return func(m string) bool {
		for _, t := range all {
			if !strings.Contains(m, t) {
				return false
			}
		}
		for _, t := range none {
			if strings.Contains(m, t) {
				return false
			}
		}
		if len(any) == 0 {
			return true
		}
		for _, t := range any {
			if strings.Contains(m, t) {
				return true
			}
		}
		return false
	}, nil
}
