package s3

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"citadel/internal/iam"
	"citadel/internal/store"
)

// Event notifications (https://docs.aws.amazon.com/AmazonS3/latest/userguide/EventNotifications.html).
//
// A bucket's notification configuration is stored with the bucket. Object
// writes and deletes are already in the change log, so a dispatcher reads the
// log from a stored cursor, matches each change against its bucket's
// configuration and delivers S3 event records to SQS queues and Lambda
// functions (asynchronous invocations). Delivery is at least once, as in S3.

// Destinations deliver events to other services. Nil functions disable that
// destination type (configurations naming it are refused).
type Destinations struct {
	QueueExists func(ctx context.Context, account, region, name string) bool
	SendMessage func(ctx context.Context, account, region, name, body string) error
	// CanInvoke reports whether the function exists and its resource policy
	// lets S3 invoke it for this bucket.
	CanInvoke   func(ctx context.Context, account, region, function, sourceARN, sourceAccount string) bool
	InvokeAsync func(ctx context.Context, account, region, function string, payload []byte) error
}

type filterRule struct {
	Name  string `xml:"Name" json:"name"`
	Value string `xml:"Value" json:"value"`
}

type notificationFilter struct {
	Rules []filterRule `xml:"S3Key>FilterRule" json:"rules,omitempty"`
}

type targetConfig struct {
	ID     string              `xml:"Id,omitempty" json:"id"`
	Target string              `xml:"-" json:"target"`
	Events []string            `xml:"Event" json:"events"`
	Filter *notificationFilter `xml:"Filter,omitempty" json:"filter,omitempty"`
}

type queueConfig struct {
	targetConfig
	Queue string `xml:"Queue"`
}

type functionConfig struct {
	targetConfig
	CloudFunction string `xml:"CloudFunction"`
}

type topicConfig struct {
	targetConfig
	Topic string `xml:"Topic"`
}

type notificationConfiguration struct {
	XMLName     xml.Name         `xml:"NotificationConfiguration"`
	Xmlns       string           `xml:"xmlns,attr,omitempty"`
	Queues      []queueConfig    `xml:"QueueConfiguration"`
	Topics      []topicConfig    `xml:"TopicConfiguration"`
	Functions   []functionConfig `xml:"CloudFunctionConfiguration"`
	EventBridge *struct{}        `xml:"EventBridgeConfiguration"`
}

// storedNotifications is the column format.
type storedNotifications struct {
	Queues    []targetConfig `json:"queues,omitempty"`
	Functions []targetConfig `json:"functions,omitempty"`
}

var notificationEvents = map[string]bool{
	"s3:ObjectCreated:*": true, "s3:ObjectCreated:Put": true, "s3:ObjectCreated:Post": true, "s3:ObjectCreated:Copy": true,
	"s3:ObjectCreated:CompleteMultipartUpload": true, "s3:ObjectRemoved:*": true, "s3:ObjectRemoved:Delete": true,
	"s3:ObjectRemoved:DeleteMarkerCreated": true, "s3:ObjectRestore:*": true, "s3:ObjectRestore:Post": true,
	"s3:ObjectRestore:Completed": true, "s3:ObjectRestore:Delete": true, "s3:ReducedRedundancyLostObject": true,
	"s3:Replication:*": true, "s3:Replication:OperationFailedReplication": true, "s3:Replication:OperationNotTracked": true,
	"s3:Replication:OperationMissedThreshold": true, "s3:Replication:OperationReplicatedAfterThreshold": true,
	"s3:LifecycleExpiration:*": true, "s3:LifecycleExpiration:Delete": true, "s3:LifecycleExpiration:DeleteMarkerCreated": true,
	"s3:LifecycleTransition": true, "s3:IntelligentTiering": true, "s3:ObjectTagging:*": true, "s3:ObjectTagging:Put": true,
	"s3:ObjectTagging:Delete": true, "s3:ObjectAcl:Put": true, "s3:ObjectCreated:PutObjectRetention": true,
}

func loadNotifications(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, bucket string) (*storedNotifications, error) {
	var raw string
	err := q.QueryRowContext(ctx, `SELECT notification FROM s3_buckets WHERE name = ?`, bucket).Scan(&raw)
	if err != nil {
		return nil, err
	}
	var n storedNotifications
	if raw != "" {
		if err := json.Unmarshal([]byte(raw), &n); err != nil {
			return nil, err
		}
	}
	return &n, nil
}

func (h *Handler) getBucketNotification(req *request) error {
	if _, err := h.bucketAccess(req, "s3:GetBucketNotification", ""); err != nil {
		return err
	}
	n, err := loadNotifications(req.ctx, h.st.DB(), req.bucket)
	if err != nil {
		return err
	}
	out := notificationConfiguration{Xmlns: "http://s3.amazonaws.com/doc/2006-03-01/"}
	for _, q := range n.Queues {
		out.Queues = append(out.Queues, queueConfig{targetConfig: q, Queue: q.Target})
	}
	for _, f := range n.Functions {
		out.Functions = append(out.Functions, functionConfig{targetConfig: f, CloudFunction: f.Target})
	}
	writeXML(req.w, http.StatusOK, out)
	return nil
}

// arnParts splits "arn:aws:sqs:region:account:name".
func arnParts(arn, service string) (region, account, name string, ok bool) {
	p := strings.SplitN(arn, ":", 7)
	if len(p) < 6 || p[0] != "arn" || p[2] != service {
		return "", "", "", false
	}
	if service == "lambda" { // arn:aws:lambda:region:account:function:name[:qualifier]
		if len(p) < 7 || p[5] != "function" {
			return "", "", "", false
		}
		return p[3], p[4], p[6], true
	}
	return p[3], p[4], p[5], true
}

func invalidDestination(arn string) error {
	return errInvalidArgument("Unable to validate the following destination configurations: %s", arn)
}

func validateTarget(t *targetConfig) error {
	if len(t.Events) == 0 {
		return errInvalidArgument("A specified event is not supported for notifications.")
	}
	for _, e := range t.Events {
		if !notificationEvents[e] {
			return errInvalidArgument("The event is not supported for notifications")
		}
	}
	if t.Filter != nil {
		seen := map[string]bool{}
		for i, r := range t.Filter.Rules {
			name := strings.ToLower(r.Name)
			if name != "prefix" && name != "suffix" {
				return errInvalidArgument("filter rule name must be either prefix or suffix")
			}
			if seen[name] {
				return errInvalidArgument("Cannot specify more than one %s rule in a filter.", name)
			}
			seen[name] = true
			t.Filter.Rules[i].Name = strings.ToUpper(name[:1]) + name[1:]
		}
	}
	if t.ID == "" {
		b := make([]byte, 16)
		_, _ = rand.Read(b)
		t.ID = hex.EncodeToString(b)
	}
	return nil
}

func (h *Handler) putBucketNotification(req *request) error {
	b, err := h.bucketAccess(req, "s3:PutBucketNotification", "")
	if err != nil {
		return err
	}
	body, err := readSmallBody(req, 256<<10, false)
	if err != nil {
		return err
	}
	var in notificationConfiguration
	if err := xml.Unmarshal(body, &in); err != nil {
		return errMalformedXML()
	}
	if len(in.Topics) > 0 || in.EventBridge != nil {
		return errNotImplemented("SNS topic and EventBridge notification destinations")
	}
	var n storedNotifications
	var testQueues []queueConfig
	for _, q := range in.Queues {
		q.Target = q.Queue
		if err := validateTarget(&q.targetConfig); err != nil {
			return err
		}
		region, account, name, ok := arnParts(q.Queue, "sqs")
		if !ok || region != b.Region || h.Events.QueueExists == nil || !h.Events.QueueExists(req.ctx, account, region, name) {
			return invalidDestination(q.Queue)
		}
		n.Queues = append(n.Queues, q.targetConfig)
		testQueues = append(testQueues, q)
	}
	for _, f := range in.Functions {
		f.Target = f.CloudFunction
		if err := validateTarget(&f.targetConfig); err != nil {
			return err
		}
		region, account, _, ok := arnParts(f.CloudFunction, "lambda")
		if !ok || region != b.Region || h.Events.CanInvoke == nil ||
			!h.Events.CanInvoke(req.ctx, account, region, f.CloudFunction, "arn:aws:s3:::"+b.Name, b.Account) {
			return invalidDestination(f.CloudFunction)
		}
		n.Functions = append(n.Functions, f.targetConfig)
	}
	stored := ""
	if len(n.Queues)+len(n.Functions) > 0 {
		raw, _ := json.Marshal(n)
		stored = string(raw)
	}
	if err := h.setBucketColumn(req, "notification", stored, "PutBucketNotification"); err != nil {
		return err
	}
	// S3 confirms a new queue destination with a test event.
	for _, q := range testQueues {
		region, account, name, _ := arnParts(q.Queue, "sqs")
		test, _ := json.Marshal(map[string]string{
			"Service": "Amazon S3", "Event": "s3:TestEvent", "Time": time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
			"Bucket": b.Name, "RequestId": req.w.Header().Get("x-amz-request-id"), "HostId": req.w.Header().Get("x-amz-id-2"),
		})
		_ = h.Events.SendMessage(req.ctx, account, region, name, string(test))
	}
	req.w.WriteHeader(http.StatusOK)
	return nil
}

// ---- change log fields ----------------------------------------------------------------

// createdEvent names how an object was created, as S3 events do.
func createdEvent(req *request) string {
	if req.r == nil {
		return "Put"
	}
	switch {
	case req.r.Method == http.MethodPost && req.r.URL.Query().Has("uploadId"):
		return "CompleteMultipartUpload"
	case req.r.Header.Get("x-amz-copy-source") != "":
		return "Copy"
	case req.r.Method == http.MethodPost:
		return "Post"
	}
	return "Put"
}

// eventFields adds who made a change and from where, for event records.
func eventFields(req *request, m map[string]any) map[string]any {
	if req.who != nil {
		arn, id := iam.Identity(req.who)
		if id == "" {
			id = arn
		}
		m["principal"] = "AWS:" + id
	} else {
		m["principal"] = "Anonymous"
	}
	if req.r != nil {
		if host, _, err := net.SplitHostPort(req.r.RemoteAddr); err == nil {
			m["ip"] = host
		}
		m["request"] = req.w.Header().Get("x-amz-request-id")
		m["host"] = req.w.Header().Get("x-amz-id-2")
	}
	return m
}

// ---- dispatcher ------------------------------------------------------------------------

const notifyCursor = "s3-notifications"

// StartNotifications delivers bucket events until ctx ends.
func (h *Handler) StartNotifications(ctx context.Context) {
	go func() {
		cursor, err := h.loadCursor(ctx)
		if err != nil {
			h.log.Error("s3 notifications: cursor", "err", err)
			return
		}
		for ctx.Err() == nil {
			next, err := h.dispatch(ctx, cursor)
			if err != nil && ctx.Err() == nil {
				h.log.Warn("s3 notifications", "err", err)
			}
			if next == cursor {
				t := time.NewTimer(200 * time.Millisecond)
				select {
				case <-ctx.Done():
					t.Stop()
					return
				case <-t.C:
				}
			}
			cursor = next
		}
	}()
}

// loadCursor resumes from the stored cursor; a new region starts at the
// current end of the log (events are not replayed from before the dispatcher existed).
func (h *Handler) loadCursor(ctx context.Context) (int64, error) {
	var seq int64
	err := h.st.DB().QueryRowContext(ctx, `SELECT seq FROM change_cursors WHERE name = ?`, notifyCursor).Scan(&seq)
	if err == nil {
		return seq, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	if err := h.st.DB().QueryRowContext(ctx, `SELECT COALESCE(MAX(seq), 0) FROM changes`).Scan(&seq); err != nil {
		return 0, err
	}
	return seq, h.saveCursor(ctx, seq)
}

func (h *Handler) saveCursor(ctx context.Context, seq int64) error {
	return h.st.Update(ctx, func(tx *store.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO change_cursors(name, seq) VALUES (?, ?)
			ON CONFLICT(name) DO UPDATE SET seq = excluded.seq`, notifyCursor, seq)
		return err
	})
}

var eventKinds = map[string]bool{"PutObject": true, "DeleteObject": true, "DeleteObjectVersion": true, "PutDeleteMarker": true}

// dispatch handles one batch of changes after cursor and returns the new cursor.
func (h *Handler) dispatch(ctx context.Context, cursor int64) (int64, error) {
	changes, err := h.st.ChangesSince(ctx, cursor, 200)
	if err != nil || len(changes) == 0 {
		return cursor, err
	}
	configs := map[string]*storedNotifications{}
	owners := map[string]string{}
	for _, ch := range changes {
		if ch.Service != "s3" || !eventKinds[ch.Kind] {
			continue
		}
		bucket, key, _ := strings.Cut(ch.Resource, "/")
		n, ok := configs[bucket]
		if !ok {
			var owner, region string
			err := h.st.DB().QueryRowContext(ctx, `SELECT a.canonical_id, b.region FROM s3_buckets b JOIN accounts a ON a.id = b.account_id WHERE b.name = ?`,
				bucket).Scan(&owner, &region)
			if err == nil {
				n, err = loadNotifications(ctx, h.st.DB(), bucket)
			}
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return cursor, err
			}
			configs[bucket], owners[bucket] = n, owner+"\x00"+region
		}
		if n == nil || len(n.Queues)+len(n.Functions) == 0 {
			continue
		}
		var p map[string]any
		_ = json.Unmarshal([]byte(ch.Payload), &p)
		name := eventName(ch.Kind, p)
		owner, region, _ := strings.Cut(owners[bucket], "\x00")
		for _, t := range n.Queues {
			if t.matches(name, key) {
				body, _ := json.Marshal(map[string]any{"Records": []any{eventRecord(ch, p, name, bucket, key, owner, region, t.ID)}})
				qRegion, qAccount, qName, _ := arnParts(t.Target, "sqs")
				if err := h.Events.SendMessage(ctx, qAccount, qRegion, qName, string(body)); err != nil {
					h.log.Warn("s3 notification to queue failed", "bucket", bucket, "queue", t.Target, "err", err)
				}
			}
		}
		for _, t := range n.Functions {
			if t.matches(name, key) {
				body, _ := json.Marshal(map[string]any{"Records": []any{eventRecord(ch, p, name, bucket, key, owner, region, t.ID)}})
				fRegion, fAccount, _, _ := arnParts(t.Target, "lambda")
				if err := h.Events.InvokeAsync(ctx, fAccount, fRegion, t.Target, body); err != nil {
					h.log.Warn("s3 notification to function failed", "bucket", bucket, "function", t.Target, "err", err)
				}
			}
		}
	}
	next := changes[len(changes)-1].Seq
	return next, h.saveCursor(ctx, next)
}

// eventName is the S3 event type ("ObjectCreated:Put") a change produces.
func eventName(kind string, p map[string]any) string {
	switch kind {
	case "PutObject":
		how, _ := p["event"].(string)
		if how == "" {
			how = "Put"
		}
		return "ObjectCreated:" + how
	case "PutDeleteMarker":
		return "ObjectRemoved:DeleteMarkerCreated"
	}
	return "ObjectRemoved:Delete"
}

func (t *targetConfig) matches(event, key string) bool {
	ok := false
	for _, e := range t.Events {
		e = strings.TrimPrefix(e, "s3:")
		if e == event || (strings.HasSuffix(e, ":*") && strings.HasPrefix(event, strings.TrimSuffix(e, "*"))) {
			ok = true
			break
		}
	}
	if !ok {
		return false
	}
	if t.Filter != nil {
		for _, r := range t.Filter.Rules {
			switch strings.ToLower(r.Name) {
			case "prefix":
				ok = ok && strings.HasPrefix(key, r.Value)
			case "suffix":
				ok = ok && strings.HasSuffix(key, r.Value)
			}
		}
	}
	return ok
}

func eventRecord(ch store.Change, p map[string]any, name, bucket, key, owner, region, configID string) map[string]any {
	str := func(k string) string { s, _ := p[k].(string); return s }
	object := map[string]any{
		"key":       strings.ReplaceAll(url.QueryEscape(key), "%2F", "/"),
		"sequencer": fmt.Sprintf("%016X", uint64(ch.HLC)),
	}
	if strings.HasPrefix(name, "ObjectCreated:") {
		size, _ := p["size"].(float64)
		object["size"] = int64(size)
		object["eTag"] = strings.Trim(str("etag"), `"`)
	}
	if v := str("version"); v != "" && v != nullVersion {
		object["versionId"] = v
	}
	return map[string]any{
		"eventVersion": "2.1", "eventSource": "aws:s3", "awsRegion": region,
		"eventTime":         ch.HLC.Time().UTC().Format("2006-01-02T15:04:05.000Z"),
		"eventName":         name,
		"userIdentity":      map[string]string{"principalId": str("principal")},
		"requestParameters": map[string]string{"sourceIPAddress": str("ip")},
		"responseElements":  map[string]string{"x-amz-request-id": str("request"), "x-amz-id-2": str("host")},
		"s3": map[string]any{
			"s3SchemaVersion": "1.0", "configurationId": configID,
			"bucket": map[string]any{"name": bucket, "ownerIdentity": map[string]string{"principalId": owner}, "arn": "arn:aws:s3:::" + bucket},
			"object": object,
		},
	}
}
