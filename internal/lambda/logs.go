package lambda

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"citadel/internal/iam"
	"citadel/internal/store"
)

// Function output is stored as CloudWatch Logs: a group per function
// (/aws/lambda/<name>), a stream per execution environment and day, and one
// event per line. logsHandler serves the part of the Logs API needed to read
// them back (and to write, for clients that ship their own logs).

type logEvent struct {
	Timestamp int64  `json:"timestamp"`
	Message   string `json:"message"`
}

// streamName names the log stream of a function version's execution
// environment, as AWS does: "2026/09/26/[$LATEST]<32 hex>". Citadel keeps
// one environment per version per day for the life of the process.
func (h *Handler) streamName(ref fnRef, version string) string {
	day := h.now().UTC().Format("2006/01/02")
	key := ref.key() + "/" + version + "/" + day
	h.mu.Lock()
	defer h.mu.Unlock()
	if s, ok := h.streams[key]; ok {
		return s
	}
	s := day + "/[" + version + "]" + randomHex(32)
	h.streams[key] = s
	return s
}

// writeLogs appends an invocation's log lines to its stream.
func (h *Handler) writeLogs(_ context.Context, ref fnRef, v *version, events []logEvent) {
	group := v.LoggingConfig["LogGroup"]
	if group == "" {
		group = "/aws/lambda/" + ref.name
	}
	stream := h.streamName(ref, v.Version)
	err := h.st.Update(context.Background(), func(tx *store.Tx) error {
		return putEvents(context.Background(), tx, ref.account, ref.region, group, stream, events, h.now().UnixMilli(), true)
	})
	if err != nil {
		h.log.Error("lambda logs", "fn", ref.name, "err", err)
	}
}

// putEvents stores events, creating the group and stream when create is set.
func putEvents(ctx context.Context, tx *store.Tx, account, region, group, stream string, events []logEvent, now int64, create bool) error {
	if create {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO logs_groups(account_id, region, name, created) VALUES (?, ?, ?, ?)`,
			account, region, group, now); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO logs_streams(account_id, region, grp, name, created) VALUES (?, ?, ?, ?, ?)`,
			account, region, group, stream, now); err != nil {
			return err
		}
	}
	for _, e := range events {
		if _, err := tx.ExecContext(ctx, `INSERT INTO logs_events(account_id, region, grp, stream, ts, ingest, message) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			account, region, group, stream, e.Timestamp, now, e.Message); err != nil {
			return err
		}
	}
	if len(events) == 0 {
		return nil
	}
	first, last := events[0].Timestamp, events[0].Timestamp
	for _, e := range events {
		first, last = min(first, e.Timestamp), max(last, e.Timestamp)
	}
	_, err := tx.ExecContext(ctx, `UPDATE logs_streams SET
			first_event = CASE WHEN first_event = 0 OR first_event > ? THEN ? ELSE first_event END,
			last_event = MAX(last_event, ?), last_ingest = ?, stored = stored + ?
		WHERE account_id=? AND region=? AND grp=? AND name=?`,
		first, first, last, now, len(events), account, region, group, stream)
	return err
}

// Logs returns the CloudWatch Logs API handler.
func (h *Handler) Logs() http.Handler { return &logsHandler{h} }

type logsHandler struct{ h *Handler }

type logsError struct {
	status  int
	code    string
	message string
}

func (e *logsError) Error() string { return e.code + ": " + e.message }

func logsErr(status int, code, msg string) *logsError { return &logsError{status, code, msg} }

func (l *logsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	op := strings.TrimPrefix(r.Header.Get("X-Amz-Target"), "Logs_20140328.")
	out, err := l.serve(r, op)
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	if err != nil {
		var le *logsError
		if !errors.As(err, &le) {
			if ae := asAPIError(err); ae.Status != 500 {
				le = logsErr(ae.Status, ae.Code, ae.Message)
			} else {
				l.h.log.Error("logs internal error", "op", op, "err", err)
				le = logsErr(500, "ServiceUnavailableException", "Internal server error")
			}
		}
		w.Header().Set("x-amzn-ErrorType", le.code)
		w.WriteHeader(le.status)
		_ = json.NewEncoder(w).Encode(map[string]string{"__type": le.code, "message": le.message})
		return
	}
	_ = json.NewEncoder(w).Encode(out)
}

type logsRequest struct {
	LogGroupName, LogGroupIdentifier, LogStreamName    string
	LogGroupNamePrefix, LogStreamNamePrefix, NextToken string
	OrderBy, FilterPattern                             string
	Descending, StartFromHead                          bool
	Limit                                              *int
	StartTime, EndTime                                 *int64
	LogStreamNames                                     []string
	LogEvents                                          []logEvent
	RetentionInDays                                    *int
}

func (l *logsHandler) serve(r *http.Request, op string) (any, error) {
	h := l.h
	auth, err := h.auth.Verify(r)
	if err != nil {
		return nil, err
	}
	if auth.Anonymous {
		return nil, logsErr(400, "MissingAuthenticationTokenException", "Missing Authentication Token")
	}
	_, who, err := h.st.LookupKey(r.Context(), auth.AccessKey)
	if err != nil {
		return nil, logsErr(400, "UnrecognizedClientException", "The security token included in the request is invalid.")
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 2<<20))
	if err != nil {
		return nil, err
	}
	var req logsRequest
	if len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			return nil, logsErr(400, "SerializationException", "Could not parse request body")
		}
	}
	if req.LogGroupName == "" && req.LogGroupIdentifier != "" {
		id := req.LogGroupIdentifier
		if i := strings.Index(id, ":log-group:"); i >= 0 {
			id = strings.TrimSuffix(id[i+len(":log-group:"):], ":*")
		}
		req.LogGroupName = id
	}
	region := auth.Region
	if region == "" {
		region = h.region
	}
	c := &logsCall{ctx: r.Context(), account: who.Account.ID, region: region, req: &req}
	if h.IAM != nil && !iam.IsRoot(&who) {
		resource := "*"
		if req.LogGroupName != "" {
			resource = c.groupARN(req.LogGroupName) + ":*"
		}
		d, err := h.IAM.Require(c.ctx, &who, "logs:"+op, []string{resource}, nil)
		if err != nil {
			return nil, err
		}
		if d != nil {
			return nil, logsErr(400, "AccessDeniedException", iam.DeniedMessage(&who, d.Action, d.Resource, d.Explicit))
		}
	}
	switch op {
	case "CreateLogGroup":
		return l.createGroup(c)
	case "DeleteLogGroup":
		return l.deleteGroup(c)
	case "DescribeLogGroups":
		return l.describeGroups(c)
	case "CreateLogStream":
		return l.createStream(c)
	case "DeleteLogStream":
		return l.deleteStream(c)
	case "DescribeLogStreams":
		return l.describeStreams(c)
	case "PutLogEvents":
		return l.putLogEvents(c)
	case "GetLogEvents":
		return l.getLogEvents(c)
	case "FilterLogEvents":
		return l.filterLogEvents(c)
	case "PutRetentionPolicy", "DeleteRetentionPolicy":
		return l.retention(c, op == "PutRetentionPolicy")
	}
	return nil, logsErr(501, "NotImplemented", "citadel: CloudWatch Logs "+op+" is not implemented yet")
}

type logsCall struct {
	ctx             context.Context
	account, region string
	req             *logsRequest
}

func (c *logsCall) groupARN(name string) string {
	return "arn:" + partition(c.region) + ":logs:" + c.region + ":" + c.account + ":log-group:" + name
}

var errNoGroup = logsErr(400, "ResourceNotFoundException", "The specified log group does not exist.")
var errNoStream = logsErr(400, "ResourceNotFoundException", "The specified log stream does not exist.")

func (l *logsHandler) groupExists(c *logsCall, q querier) error {
	if c.req.LogGroupName == "" {
		return logsErr(400, "InvalidParameterException", "1 validation error detected: Value null at 'logGroupName' failed to satisfy constraint: Member must not be null")
	}
	var one int
	err := q.QueryRowContext(c.ctx, `SELECT 1 FROM logs_groups WHERE account_id=? AND region=? AND name=?`, c.account, c.region, c.req.LogGroupName).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return errNoGroup
	}
	return err
}

func (l *logsHandler) createGroup(c *logsCall) (any, error) {
	name := c.req.LogGroupName
	if name == "" || len(name) > 512 {
		return nil, logsErr(400, "InvalidParameterException", "1 validation error detected: Value '"+name+"' at 'logGroupName' failed to satisfy constraint: Member must have length between 1 and 512")
	}
	err := l.h.st.Update(c.ctx, func(tx *store.Tx) error {
		res, err := tx.ExecContext(c.ctx, `INSERT OR IGNORE INTO logs_groups(account_id, region, name, created) VALUES (?, ?, ?, ?)`,
			c.account, c.region, name, l.h.now().UnixMilli())
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return logsErr(400, "ResourceAlreadyExistsException", "The specified log group already exists")
		}
		return tx.Change("logs", "CreateLogGroup", c.groupARN(name), nil)
	})
	return map[string]any{}, err
}

func (l *logsHandler) deleteGroup(c *logsCall) (any, error) {
	err := l.h.st.Update(c.ctx, func(tx *store.Tx) error {
		res, err := tx.ExecContext(c.ctx, `DELETE FROM logs_groups WHERE account_id=? AND region=? AND name=?`, c.account, c.region, c.req.LogGroupName)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return errNoGroup
		}
		return tx.Change("logs", "DeleteLogGroup", c.groupARN(c.req.LogGroupName), nil)
	})
	return map[string]any{}, err
}

func (l *logsHandler) retention(c *logsCall, put bool) (any, error) {
	days := 0
	if put {
		if c.req.RetentionInDays == nil {
			return nil, logsErr(400, "InvalidParameterException", "1 validation error detected: Value null at 'retentionInDays' failed to satisfy constraint: Member must not be null")
		}
		days = *c.req.RetentionInDays
	}
	err := l.h.st.Update(c.ctx, func(tx *store.Tx) error {
		res, err := tx.ExecContext(c.ctx, `UPDATE logs_groups SET retention=? WHERE account_id=? AND region=? AND name=?`, days, c.account, c.region, c.req.LogGroupName)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return errNoGroup
		}
		return nil
	})
	return map[string]any{}, err
}

// limitOf clamps a request's limit.
func limitOf(p *int, def, most int) (int, error) {
	if p == nil {
		return def, nil
	}
	if *p < 1 || *p > most {
		return 0, logsErr(400, "InvalidParameterException", "1 validation error detected: Value '"+strconv.Itoa(*p)+"' at 'limit' failed to satisfy constraint: Member must have value less than or equal to "+strconv.Itoa(most))
	}
	return *p, nil
}

func (l *logsHandler) describeGroups(c *logsCall) (any, error) {
	limit, err := limitOf(c.req.Limit, 50, 50)
	if err != nil {
		return nil, err
	}
	rows, err := l.h.st.DB().QueryContext(c.ctx, `SELECT g.name, g.created, g.retention,
			(SELECT COALESCE(SUM(LENGTH(message)), 0) FROM logs_events e WHERE e.account_id=g.account_id AND e.region=g.region AND e.grp=g.name)
		FROM logs_groups g WHERE g.account_id=? AND g.region=? AND g.name >= ? AND g.name > ? ORDER BY g.name LIMIT ?`,
		c.account, c.region, c.req.LogGroupNamePrefix, c.req.NextToken, limit+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	groups := []map[string]any{}
	out := map[string]any{}
	for rows.Next() {
		var name string
		var created, stored int64
		var retention int
		if err := rows.Scan(&name, &created, &retention, &stored); err != nil {
			return nil, err
		}
		if !strings.HasPrefix(name, c.req.LogGroupNamePrefix) {
			break
		}
		if len(groups) == limit {
			out["nextToken"] = groups[len(groups)-1]["logGroupName"]
			break
		}
		g := map[string]any{
			"logGroupName": name, "creationTime": created, "metricFilterCount": 0,
			"arn": c.groupARN(name) + ":*", "logGroupArn": c.groupARN(name), "storedBytes": stored, "logGroupClass": "STANDARD",
		}
		if retention > 0 {
			g["retentionInDays"] = retention
		}
		groups = append(groups, g)
	}
	out["logGroups"] = groups
	return out, rows.Err()
}

func (l *logsHandler) createStream(c *logsCall) (any, error) {
	if c.req.LogStreamName == "" || len(c.req.LogStreamName) > 512 || strings.ContainsAny(c.req.LogStreamName, ":*") {
		return nil, logsErr(400, "InvalidParameterException", "1 validation error detected: Value '"+c.req.LogStreamName+"' at 'logStreamName' failed to satisfy constraint: Member must satisfy regular expression pattern: [^:*]*")
	}
	err := l.h.st.Update(c.ctx, func(tx *store.Tx) error {
		if err := l.groupExists(c, tx); err != nil {
			return err
		}
		res, err := tx.ExecContext(c.ctx, `INSERT OR IGNORE INTO logs_streams(account_id, region, grp, name, created) VALUES (?, ?, ?, ?, ?)`,
			c.account, c.region, c.req.LogGroupName, c.req.LogStreamName, l.h.now().UnixMilli())
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return logsErr(400, "ResourceAlreadyExistsException", "The specified log stream already exists")
		}
		return nil
	})
	return map[string]any{}, err
}

func (l *logsHandler) deleteStream(c *logsCall) (any, error) {
	err := l.h.st.Update(c.ctx, func(tx *store.Tx) error {
		if err := l.groupExists(c, tx); err != nil {
			return err
		}
		res, err := tx.ExecContext(c.ctx, `DELETE FROM logs_streams WHERE account_id=? AND region=? AND grp=? AND name=?`,
			c.account, c.region, c.req.LogGroupName, c.req.LogStreamName)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return errNoStream
		}
		return nil
	})
	return map[string]any{}, err
}

func (l *logsHandler) describeStreams(c *logsCall) (any, error) {
	db := l.h.st.DB()
	if err := l.groupExists(c, db); err != nil {
		return nil, err
	}
	limit, err := limitOf(c.req.Limit, 50, 50)
	if err != nil {
		return nil, err
	}
	byTime := c.req.OrderBy == "LastEventTime"
	if byTime && c.req.LogStreamNamePrefix != "" {
		return nil, logsErr(400, "InvalidParameterException", "Cannot order by LastEventTime with a logStreamNamePrefix.")
	}
	order := "name"
	if byTime {
		order = "last_event"
	}
	if c.req.Descending {
		order += " DESC"
	}
	offset := 0
	if c.req.NextToken != "" {
		if offset, err = strconv.Atoi(c.req.NextToken); err != nil {
			return nil, logsErr(400, "InvalidParameterException", "The specified nextToken is invalid.")
		}
	}
	rows, err := db.QueryContext(c.ctx, `SELECT name, created, first_event, last_event, last_ingest,
			(SELECT COALESCE(SUM(LENGTH(message)), 0) FROM logs_events e WHERE e.account_id=s.account_id AND e.region=s.region AND e.grp=s.grp AND e.stream=s.name)
		FROM logs_streams s WHERE account_id=? AND region=? AND grp=? AND substr(name, 1, ?) = ?
		ORDER BY `+order+`, name LIMIT ? OFFSET ?`,
		c.account, c.region, c.req.LogGroupName, len(c.req.LogStreamNamePrefix), c.req.LogStreamNamePrefix, limit+1, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	streams := []map[string]any{}
	out := map[string]any{}
	for rows.Next() {
		var name string
		var created, first, last, ingest, stored int64
		if err := rows.Scan(&name, &created, &first, &last, &ingest, &stored); err != nil {
			return nil, err
		}
		if len(streams) == limit {
			out["nextToken"] = strconv.Itoa(offset + limit)
			break
		}
		s := map[string]any{
			"logStreamName": name, "creationTime": created, "storedBytes": stored,
			"arn": c.groupARN(c.req.LogGroupName) + ":log-stream:" + name,
		}
		if last > 0 {
			s["firstEventTimestamp"] = first
			s["lastEventTimestamp"] = last
			s["lastIngestionTime"] = ingest
		}
		streams = append(streams, s)
	}
	out["logStreams"] = streams
	return out, rows.Err()
}

func (l *logsHandler) putLogEvents(c *logsCall) (any, error) {
	if len(c.req.LogEvents) == 0 {
		return nil, logsErr(400, "InvalidParameterException", "1 validation error detected: Value '[]' at 'logEvents' failed to satisfy constraint: Member must have length greater than or equal to 1")
	}
	for i := 1; i < len(c.req.LogEvents); i++ {
		if c.req.LogEvents[i].Timestamp < c.req.LogEvents[i-1].Timestamp {
			return nil, logsErr(400, "InvalidParameterException", "Log events in a single PutLogEvents request must be in chronological order.")
		}
	}
	err := l.h.st.Update(c.ctx, func(tx *store.Tx) error {
		if err := l.groupExists(c, tx); err != nil {
			return err
		}
		var one int
		err := tx.QueryRowContext(c.ctx, `SELECT 1 FROM logs_streams WHERE account_id=? AND region=? AND grp=? AND name=?`,
			c.account, c.region, c.req.LogGroupName, c.req.LogStreamName).Scan(&one)
		if errors.Is(err, sql.ErrNoRows) {
			return errNoStream
		}
		if err != nil {
			return err
		}
		return putEvents(c.ctx, tx, c.account, c.region, c.req.LogGroupName, c.req.LogStreamName, c.req.LogEvents, l.h.now().UnixMilli(), false)
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"nextSequenceToken": strconv.FormatInt(l.h.now().UnixNano(), 10)}, nil
}

func (l *logsHandler) getLogEvents(c *logsCall) (any, error) {
	db := l.h.st.DB()
	if err := l.groupExists(c, db); err != nil {
		return nil, err
	}
	var one int
	err := db.QueryRowContext(c.ctx, `SELECT 1 FROM logs_streams WHERE account_id=? AND region=? AND grp=? AND name=?`,
		c.account, c.region, c.req.LogGroupName, c.req.LogStreamName).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errNoStream
	}
	if err != nil {
		return nil, err
	}
	limit, err := limitOf(c.req.Limit, 10000, 10000)
	if err != nil {
		return nil, err
	}
	where := `account_id=? AND region=? AND grp=? AND stream=?`
	args := []any{c.account, c.region, c.req.LogGroupName, c.req.LogStreamName}
	if c.req.StartTime != nil {
		where += ` AND ts >= ?`
		args = append(args, *c.req.StartTime)
	}
	if c.req.EndTime != nil {
		where += ` AND ts < ?`
		args = append(args, *c.req.EndTime)
	}
	forward := c.req.StartFromHead
	if t := c.req.NextToken; t != "" {
		n, err := strconv.ParseInt(t[min(2, len(t)):], 10, 64)
		if err != nil || (!strings.HasPrefix(t, "f/") && !strings.HasPrefix(t, "b/")) {
			return nil, logsErr(400, "InvalidParameterException", "The specified nextToken is invalid.")
		}
		forward = strings.HasPrefix(t, "f/")
		if forward {
			where += ` AND id > ?`
		} else {
			where += ` AND id < ?`
		}
		args = append(args, n)
	}
	order := "DESC"
	if forward {
		order = "ASC"
	}
	rows, err := db.QueryContext(c.ctx, `SELECT id, ts, ingest, message FROM logs_events WHERE `+where+` ORDER BY id `+order+` LIMIT ?`, append(args, limit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type ev struct {
		id         int64
		ts, ingest int64
		message    string
	}
	var evs []ev
	for rows.Next() {
		var e ev
		if err := rows.Scan(&e.id, &e.ts, &e.ingest, &e.message); err != nil {
			return nil, err
		}
		evs = append(evs, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if !forward {
		for i, j := 0, len(evs)-1; i < j; i, j = i+1, j-1 {
			evs[i], evs[j] = evs[j], evs[i]
		}
	}
	events := []map[string]any{}
	for _, e := range evs {
		events = append(events, map[string]any{"timestamp": e.ts, "message": e.message, "ingestionTime": e.ingest})
	}
	out := map[string]any{"events": events}
	if len(evs) > 0 {
		out["nextForwardToken"] = "f/" + strconv.FormatInt(evs[len(evs)-1].id, 10)
		out["nextBackwardToken"] = "b/" + strconv.FormatInt(evs[0].id, 10)
	} else {
		// At either end the token stays where it is, which tells clients
		// that paged through everything to stop.
		tok := c.req.NextToken
		if tok == "" {
			tok = "f/0"
		}
		out["nextForwardToken"], out["nextBackwardToken"] = tok, "b/0"
		if strings.HasPrefix(tok, "b/") {
			out["nextForwardToken"], out["nextBackwardToken"] = "f/0", tok
		}
	}
	return out, nil
}

func (l *logsHandler) filterLogEvents(c *logsCall) (any, error) {
	db := l.h.st.DB()
	if err := l.groupExists(c, db); err != nil {
		return nil, err
	}
	if len(c.req.LogStreamNames) > 0 && c.req.LogStreamNamePrefix != "" {
		return nil, logsErr(400, "InvalidParameterException", "Cannot specify both logStreamNames and logStreamNamePrefix.")
	}
	limit, err := limitOf(c.req.Limit, 10000, 10000)
	if err != nil {
		return nil, err
	}
	where := `account_id=? AND region=? AND grp=?`
	args := []any{c.account, c.region, c.req.LogGroupName}
	if len(c.req.LogStreamNames) > 0 {
		where += ` AND stream IN (` + strings.TrimSuffix(strings.Repeat("?,", len(c.req.LogStreamNames)), ",") + `)`
		for _, s := range c.req.LogStreamNames {
			args = append(args, s)
		}
	}
	if p := c.req.LogStreamNamePrefix; p != "" {
		where += ` AND substr(stream, 1, ?) = ?`
		args = append(args, len(p), p)
	}
	if c.req.StartTime != nil {
		where += ` AND ts >= ?`
		args = append(args, *c.req.StartTime)
	}
	if c.req.EndTime != nil {
		where += ` AND ts <= ?`
		args = append(args, *c.req.EndTime)
	}
	if c.req.NextToken != "" {
		n, err := strconv.ParseInt(c.req.NextToken, 10, 64)
		if err != nil {
			return nil, logsErr(400, "InvalidParameterException", "The specified nextToken is invalid.")
		}
		where += ` AND id > ?`
		args = append(args, n)
	}
	match := compileFilter(c.req.FilterPattern)
	rows, err := db.QueryContext(c.ctx, `SELECT id, stream, ts, ingest, message FROM logs_events WHERE `+where+` ORDER BY ts, id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	events := []map[string]any{}
	out := map[string]any{}
	for rows.Next() {
		var id, ts, ingest int64
		var stream, message string
		if err := rows.Scan(&id, &stream, &ts, &ingest, &message); err != nil {
			return nil, err
		}
		if !match(message) {
			continue
		}
		if len(events) == limit {
			out["nextToken"] = events[len(events)-1]["eventId"]
			break
		}
		events = append(events, map[string]any{
			"logStreamName": stream, "timestamp": ts, "message": message, "ingestionTime": ingest,
			"eventId": strconv.FormatInt(id, 10),
		})
	}
	out["events"] = events
	out["searchedLogStreams"] = []any{}
	return out, rows.Err()
}

// compileFilter implements CloudWatch Logs' term filter patterns: every term
// must appear (quoted terms may contain spaces), "-term" must not, and
// "?term" alternatives match if any does. JSON and space-delimited field
// patterns are not supported yet and match everything.
func compileFilter(pattern string) func(string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" || strings.HasPrefix(pattern, "{") || strings.HasPrefix(pattern, "[") {
		return func(string) bool { return true }
	}
	var must, not, any []string
	for _, t := range splitTerms(pattern) {
		switch {
		case strings.HasPrefix(t, "?"):
			any = append(any, strings.Trim(t[1:], `"`))
		case strings.HasPrefix(t, "-") && len(t) > 1:
			not = append(not, strings.Trim(t[1:], `"`))
		default:
			must = append(must, strings.Trim(t, `"`))
		}
	}
	return func(msg string) bool {
		for _, t := range must {
			if !strings.Contains(msg, t) {
				return false
			}
		}
		for _, t := range not {
			if strings.Contains(msg, t) {
				return false
			}
		}
		if len(any) == 0 {
			return true
		}
		for _, t := range any {
			if strings.Contains(msg, t) {
				return true
			}
		}
		return false
	}
}

// splitTerms splits on spaces outside double quotes.
func splitTerms(s string) []string {
	var out []string
	var cur strings.Builder
	quoted := false
	for _, r := range s {
		switch {
		case r == '"':
			quoted = !quoted
			cur.WriteRune(r)
		case r == ' ' && !quoted:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}
