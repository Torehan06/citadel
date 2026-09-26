package s3

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"citadel/internal/store"
)

// Event notifications. PutBucketNotificationConfiguration stores which
// events go to which SQS queues and Lambda functions. A notifier then reads
// the region's change log (never the object tables) and turns each object
// change into an S3 event record for every matching destination, so a
// notification is sent exactly for what was committed, in commit order.

// NotifyTargets delivers events to other services in the region.
type NotifyTargets interface {
	QueueExists(ctx context.Context, arn string) bool
	FunctionExists(ctx context.Context, arn string) bool
	SendToQueue(ctx context.Context, arn, body string) error
	InvokeAsync(ctx context.Context, functionARN string, payload []byte) error
}

type notificationConfiguration struct {
	XMLName     xml.Name       `xml:"http://s3.amazonaws.com/doc/2006-03-01/ NotificationConfiguration" json:"-"`
	Topics      []notifyTarget `xml:"TopicConfiguration" json:",omitempty"`
	Queues      []notifyTarget `xml:"QueueConfiguration" json:",omitempty"`
	Functions   []notifyTarget `xml:"CloudFunctionConfiguration" json:",omitempty"`
	EventBridge *struct{}      `xml:"EventBridgeConfiguration" json:",omitempty"`
}

type notifyTarget struct {
	Id            string        `xml:"Id,omitempty"`
	Topic         string        `xml:"Topic,omitempty"`
	Queue         string        `xml:"Queue,omitempty"`
	CloudFunction string        `xml:"CloudFunction,omitempty"`
	Events        []string      `xml:"Event"`
	Filter        *notifyFilter `xml:"Filter,omitempty" json:",omitempty"`
}

type notifyFilter struct {
	Rules []filterRule `xml:"S3Key>FilterRule"`
}

type filterRule struct {
	Name  string `xml:"Name"`
	Value string `xml:"Value"`
}

func (t *notifyTarget) arn() string { return t.Topic + t.Queue + t.CloudFunction }

// rules returns the key prefix and suffix the target is limited to.
func (t *notifyTarget) rules() (prefix, suffix string) {
	if t.Filter == nil {
		return "", ""
	}
	for _, r := range t.Filter.Rules {
		switch strings.ToLower(r.Name) {
		case "prefix":
			prefix = r.Value
		case "suffix":
			suffix = r.Value
		}
	}
	return prefix, suffix
}

// notificationEvents are the event types S3 can publish.
var notificationEvents = map[string]bool{}

func init() {
	for _, e := range []string{
		"s3:ReducedRedundancyLostObject",
		"s3:ObjectCreated:*", "s3:ObjectCreated:Put", "s3:ObjectCreated:Post", "s3:ObjectCreated:Copy", "s3:ObjectCreated:CompleteMultipartUpload",
		"s3:ObjectRemoved:*", "s3:ObjectRemoved:Delete", "s3:ObjectRemoved:DeleteMarkerCreated",
		"s3:ObjectRestore:*", "s3:ObjectRestore:Post", "s3:ObjectRestore:Completed", "s3:ObjectRestore:Delete",
		"s3:Replication:*", "s3:Replication:OperationFailedReplication", "s3:Replication:OperationNotTracked",
		"s3:Replication:OperationMissedThreshold", "s3:Replication:OperationReplicatedAfterThreshold",
		"s3:LifecycleTransition", "s3:IntelligentTiering", "s3:ObjectAcl:Put",
		"s3:LifecycleExpiration:*", "s3:LifecycleExpiration:Delete", "s3:LifecycleExpiration:DeleteMarkerCreated",
		"s3:ObjectTagging:*", "s3:ObjectTagging:Put", "s3:ObjectTagging:Delete",
	} {
		notificationEvents[e] = true
	}
}

// eventMatches reports whether a configured event type (possibly "…:*")
// covers an event name like "ObjectCreated:Put".
func eventMatches(configured, name string) bool {
	configured = strings.TrimPrefix(configured, "s3:")
	if strings.HasSuffix(configured, ":*") {
		return strings.HasPrefix(name, strings.TrimSuffix(configured, "*"))
	}
	return configured == name
}

// eventsOverlap reports whether two configured event types can both match
// one event.
func eventsOverlap(a, b string) bool {
	fa, fb := strings.TrimPrefix(a, "s3:"), strings.TrimPrefix(b, "s3:")
	fam := func(s string) string { return strings.SplitN(s, ":", 2)[0] }
	if fam(fa) != fam(fb) {
		return false
	}
	return strings.HasSuffix(fa, ":*") || strings.HasSuffix(fb, ":*") || fa == fb
}

func errInvalidNotification(msg string) error {
	return &Error{Status: 400, Code: "InvalidArgument", Message: msg}
}

// parseNotification decodes and validates a notification configuration.
func (h *Handler) parseNotification(ctx context.Context, body []byte) (*notificationConfiguration, error) {
	var cfg notificationConfiguration
	if err := xml.Unmarshal(body, &cfg); err != nil {
		return nil, errMalformedXML()
	}
	var all []*notifyTarget
	for _, list := range [][]notifyTarget{cfg.Topics, cfg.Queues, cfg.Functions} {
		for i := range list {
			all = append(all, &list[i])
		}
	}
	var unreachable []string
	for _, t := range all {
		if t.Id == "" {
			t.Id = notifyID()
		}
		if len(t.Events) == 0 {
			return nil, errMalformedXML()
		}
		for _, e := range t.Events {
			if !notificationEvents[e] {
				return nil, errInvalidNotification("The event is not supported for notifications")
			}
		}
		if t.Filter != nil {
			seen := map[string]bool{}
			for _, r := range t.Filter.Rules {
				name := strings.ToLower(r.Name)
				if name != "prefix" && name != "suffix" {
					return nil, errInvalidNotification("filter rule name must be either prefix or suffix")
				}
				if seen[name] {
					return nil, errInvalidNotification("Cannot specify more than one " + name + " rule in a filter.")
				}
				seen[name] = true
			}
		}
		ok := false
		switch {
		case h.Notify == nil:
		case t.Queue != "":
			ok = h.Notify.QueueExists(ctx, t.Queue)
		case t.CloudFunction != "":
			ok = h.Notify.FunctionExists(ctx, t.CloudFunction)
		}
		if !ok {
			unreachable = append(unreachable, t.arn())
		}
	}
	if len(unreachable) > 0 {
		return nil, &Error{Status: 400, Code: "InvalidArgument", Message: "Unable to validate the following destination configurations"}
	}
	for i, a := range all {
		for _, b := range all[i+1:] {
			if targetsOverlap(a, b) {
				return nil, errInvalidNotification("Configurations overlap. Configurations on the same bucket cannot share a common event type.")
			}
		}
	}
	return &cfg, nil
}

// targetsOverlap: two configurations overlap when some event type and some
// key could match both.
func targetsOverlap(a, b *notifyTarget) bool {
	shared := false
	for _, ea := range a.Events {
		for _, eb := range b.Events {
			shared = shared || eventsOverlap(ea, eb)
		}
	}
	if !shared {
		return false
	}
	pa, sa := a.rules()
	pb, sb := b.rules()
	prefixes := strings.HasPrefix(pa, pb) || strings.HasPrefix(pb, pa)
	suffixes := strings.HasSuffix(sa, sb) || strings.HasSuffix(sb, sa)
	return prefixes && suffixes
}

func (h *Handler) getBucketNotification(req *request) error {
	b, err := h.bucketAccess(req, "s3:GetBucketNotification", "")
	if err != nil {
		return err
	}
	cfg := notificationConfiguration{}
	if b.Notification != "" {
		if err := json.Unmarshal([]byte(b.Notification), &cfg); err != nil {
			return err
		}
	}
	writeXML(req.w, http.StatusOK, cfg)
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
	cfg, err := h.parseNotification(req.ctx, body)
	if err != nil {
		return err
	}
	raw := ""
	if len(cfg.Topics)+len(cfg.Queues)+len(cfg.Functions) > 0 || cfg.EventBridge != nil {
		j, _ := json.Marshal(cfg)
		raw = string(j)
	}
	if err := h.setBucketColumn(req, "notification", raw, "PutBucketNotification"); err != nil {
		return err
	}
	// Like AWS, confirm each new queue destination with a test event.
	if h.Notify != nil {
		for _, q := range cfg.Queues {
			test := map[string]string{
				"Service": "Amazon S3", "Event": "s3:TestEvent", "Time": time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
				"Bucket": b.Name, "RequestId": req.w.Header().Get("x-amz-request-id"), "HostId": hostID(),
			}
			j, _ := json.Marshal(test)
			_ = h.Notify.SendToQueue(req.ctx, q.Queue, string(j))
		}
	}
	req.w.WriteHeader(http.StatusOK)
	return nil
}

func hostID() string { return notifyID() + notifyID() }

// notifyID is a random identifier (configuration IDs, x-amz-id-2).
func notifyID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// eventMeta is what a change-log entry records about the request behind an
// object change, for the notifications it triggers. Changes made without an
// HTTP request (lifecycle expiry) carry none.
func eventMeta(req *request) map[string]any {
	m := map[string]any{}
	if req.w != nil {
		m["request_id"] = req.w.Header().Get("x-amz-request-id")
	}
	if req.who != nil {
		m["requester"] = req.who.Account.ID
	}
	if req.r != nil {
		if host, _, err := net.SplitHostPort(req.r.RemoteAddr); err == nil {
			m["ip"] = host
		}
	}
	return m
}

// withMeta adds eventMeta to a change payload.
func withMeta(req *request, payload map[string]any) map[string]any {
	for k, v := range eventMeta(req) {
		payload[k] = v
	}
	return payload
}

// createEvent names the ObjectCreated event a write request causes.
func createEvent(req *request) string {
	if req.r == nil {
		return "Put"
	}
	switch {
	case req.r.Header.Get("x-amz-copy-source") != "":
		return "Copy"
	case req.r.Method == http.MethodPost && req.r.URL.Query().Has("uploadId"):
		return "CompleteMultipartUpload"
	case req.r.Method == http.MethodPost:
		return "Post"
	}
	return "Put"
}

// ---- the notifier ------------------------------------------------------------

const notifierCursor = "s3-notifications"

// StartNotifier follows the change log and delivers bucket notifications.
func (h *Handler) StartNotifier(ctx context.Context) error {
	cursor, err := h.loadCursor(ctx)
	if err != nil {
		return err
	}
	go func() {
		t := time.NewTicker(100 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			next, err := h.notifyBatch(ctx, cursor)
			if err != nil {
				if ctx.Err() == nil {
					h.log.Error("s3 notifications", "err", err)
				}
				continue
			}
			cursor = next
		}
	}()
	return nil
}

// loadCursor returns the last change delivered, starting at the head of the
// log the first time so history is not replayed.
func (h *Handler) loadCursor(ctx context.Context) (int64, error) {
	var seq int64
	err := h.st.DB().QueryRowContext(ctx, `SELECT seq FROM feed_cursors WHERE name = ?`, notifierCursor).Scan(&seq)
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
		_, err := tx.ExecContext(ctx, `INSERT INTO feed_cursors(name, seq) VALUES (?, ?)
			ON CONFLICT(name) DO UPDATE SET seq = excluded.seq`, notifierCursor, seq)
		return err
	})
}

// notifyBatch delivers the notifications of the next changes after cursor.
func (h *Handler) notifyBatch(ctx context.Context, cursor int64) (int64, error) {
	changes, err := h.st.ChangesSince(ctx, cursor, 256)
	if err != nil || len(changes) == 0 {
		return cursor, err
	}
	configs := map[string]*bucketNotify{}
	for _, c := range changes {
		if c.Service == "s3" {
			if err := h.notifyChange(ctx, c, configs); err != nil {
				h.log.Warn("s3 notification", "seq", c.Seq, "err", err)
			}
		}
		cursor = c.Seq
	}
	return cursor, h.saveCursor(ctx, cursor)
}

type bucketNotify struct {
	cfg           *notificationConfiguration
	region, owner string
}

func (h *Handler) bucketNotifyConfig(ctx context.Context, bucket string, cache map[string]*bucketNotify) (*bucketNotify, error) {
	if bn, ok := cache[bucket]; ok {
		return bn, nil
	}
	var raw, region, owner string
	err := h.st.DB().QueryRowContext(ctx, `SELECT notification, region, account_id FROM s3_buckets WHERE name = ?`, bucket).Scan(&raw, &region, &owner)
	if errors.Is(err, sql.ErrNoRows) {
		cache[bucket] = nil
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	bn := &bucketNotify{region: region, owner: owner}
	if raw != "" {
		var cfg notificationConfiguration
		if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
			return nil, err
		}
		bn.cfg = &cfg
	}
	cache[bucket] = bn
	return bn, nil
}

// changeEvents maps change-log kinds to S3 event names.
func changeEvent(kind string, payload map[string]any) string {
	switch kind {
	case "PutObject":
		if e, _ := payload["event"].(string); e != "" {
			return "ObjectCreated:" + e
		}
		return "ObjectCreated:Put"
	case "DeleteObject", "DeleteObjectVersion":
		return "ObjectRemoved:Delete"
	case "PutDeleteMarker":
		return "ObjectRemoved:DeleteMarkerCreated"
	case "PutObjectAcl":
		return "ObjectAcl:Put"
	case "PutObjectTagging":
		return "ObjectTagging:Put"
	case "DeleteObjectTagging":
		return "ObjectTagging:Delete"
	}
	return ""
}

func (h *Handler) notifyChange(ctx context.Context, c store.Change, cache map[string]*bucketNotify) error {
	var payload map[string]any
	if c.Payload != "" {
		if err := json.Unmarshal([]byte(c.Payload), &payload); err != nil {
			return err
		}
	}
	name := changeEvent(c.Kind, payload)
	bucket, key, ok := strings.Cut(c.Resource, "/")
	if name == "" || !ok {
		return nil
	}
	bn, err := h.bucketNotifyConfig(ctx, bucket, cache)
	if err != nil || bn == nil || bn.cfg == nil || h.Notify == nil {
		return err
	}
	for _, list := range [][]notifyTarget{bn.cfg.Queues, bn.cfg.Functions} {
		for i := range list {
			t := &list[i]
			if !targetMatches(t, name, key) {
				continue
			}
			rec := eventRecord(c, bn, bucket, key, name, t.Id, payload)
			body, _ := json.Marshal(map[string]any{"Records": []any{rec}})
			var err error
			if t.Queue != "" {
				err = h.Notify.SendToQueue(ctx, t.Queue, string(body))
			} else {
				err = h.Notify.InvokeAsync(ctx, t.CloudFunction, body)
			}
			if err != nil {
				h.log.Warn("s3 notification delivery", "bucket", bucket, "target", t.arn(), "err", err)
			}
		}
	}
	return nil
}

// eventKey URL-encodes a key the way event records carry it: form encoding
// (a space is "+"), with "/" left as is.
func eventKey(key string) string { return strings.ReplaceAll(url.QueryEscape(key), "%2F", "/") }

func targetMatches(t *notifyTarget, name, key string) bool {
	prefix, suffix := t.rules()
	if !strings.HasPrefix(key, prefix) || !strings.HasSuffix(key, suffix) {
		return false
	}
	for _, e := range t.Events {
		if eventMatches(e, name) {
			return true
		}
	}
	return false
}

// eventRecord builds one S3 event notification record.
func eventRecord(c store.Change, bn *bucketNotify, bucket, key, name, configID string, p map[string]any) map[string]any {
	str := func(k string) string { s, _ := p[k].(string); return s }
	principal := "AWS:" + bn.owner
	if r := str("requester"); r != "" {
		principal = "AWS:" + r
	}
	obj := map[string]any{"key": eventKey(key), "sequencer": fmt.Sprintf("%016X", c.Seq)}
	if strings.HasPrefix(name, "ObjectCreated:") {
		obj["size"] = p["size"]
		obj["eTag"] = strings.Trim(str("etag"), `"`)
	}
	if v := str("version"); v != "" && v != "null" {
		obj["versionId"] = v
	}
	return map[string]any{
		"eventVersion": "2.1",
		"eventSource":  "aws:s3",
		"awsRegion":    bn.region,
		"eventTime":    time.UnixMilli(c.HLC.WallMs()).UTC().Format("2006-01-02T15:04:05.000Z"),
		"eventName":    name,
		"userIdentity": map[string]string{"principalId": principal},
		"requestParameters": map[string]string{
			"sourceIPAddress": str("ip"),
		},
		"responseElements": map[string]string{
			"x-amz-request-id": str("request_id"),
			"x-amz-id-2":       hostID(),
		},
		"s3": map[string]any{
			"s3SchemaVersion": "1.0",
			"configurationId": configID,
			"bucket": map[string]any{
				"name":          bucket,
				"ownerIdentity": map[string]string{"principalId": bn.owner},
				"arn":           "arn:aws:s3:::" + bucket,
			},
			"object": obj,
		},
	}
}
