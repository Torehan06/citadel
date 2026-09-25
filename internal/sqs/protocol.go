package sqs

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// Query uses numbered flat lists and maps. Decode into the same request model
// as JSON, so validation and state transitions cannot drift between protocols.
func decodeQuery(v url.Values) (string, request, error) {
	op := v.Get("Action")
	r, err := queryRequest(v, "")
	if err != nil {
		return op, r, err
	}
	for i := 1; ; i++ {
		prefix := op + "RequestEntry." + strconv.Itoa(i) + "."
		if _, ok := v[prefix+"Id"]; !ok {
			break
		}
		entry, err := queryRequest(v, prefix)
		if err != nil {
			return op, r, err
		}
		r.Entries = append(r.Entries, entry)
	}
	return op, r, nil
}
func queryRequest(v url.Values, p string) (request, error) {
	obj := map[string]any{}
	for _, k := range strings.Fields("QueueName QueueUrl QueueOwnerAWSAccountId QueueNamePrefix NextToken MessageBody MessageGroupId MessageDeduplicationId ReceiptHandle Id Label") {
		if s, ok := v[p+k]; ok {
			obj[k] = s[0]
		}
	}
	for _, k := range strings.Fields("MaxResults DelaySeconds VisibilityTimeout WaitTimeSeconds MaxNumberOfMessages") {
		if s, ok := v[p+k]; ok {
			n, err := strconv.Atoi(s[0])
			if err != nil {
				return request{}, fmt.Errorf("%s must be an integer", k)
			}
			obj[k] = n
		}
	}
	for _, pair := range [][2]string{{"AttributeName", "AttributeNames"}, {"MessageAttributeName", "MessageAttributeNames"}, {"MessageSystemAttributeName", "MessageSystemAttributeNames"}, {"TagKey", "TagKeys"}, {"AWSAccountId", "AWSAccountIds"}, {"ActionName", "Actions"}} {
		var values []string
		for i := 1; ; i++ {
			s, ok := v[p+pair[0]+"."+strconv.Itoa(i)]
			if !ok {
				break
			}
			values = append(values, s[0])
		}
		if len(values) > 0 {
			obj[pair[1]] = values
		}
	}
	for _, pair := range [][2]string{{"Attribute", "Attributes"}, {"Tag", "Tags"}, {"MessageAttribute", "MessageAttributes"}, {"MessageSystemAttribute", "MessageSystemAttributes"}} {
		values := map[string]any{}
		for i := 1; ; i++ {
			prefix := p + pair[0] + "." + strconv.Itoa(i) + "."
			name := v.Get(prefix + "Name")
			if pair[0] == "Tag" {
				name = v.Get(prefix + "Key")
			}
			if name == "" {
				break
			}
			if strings.HasPrefix(pair[0], "Message") {
				a := map[string]any{}
				for _, k := range []string{"DataType", "StringValue", "BinaryValue"} {
					if s, ok := v[prefix+"Value."+k]; ok {
						a[k] = s[0]
					}
				}
				values[name] = a
			} else {
				values[name] = v.Get(prefix + "Value")
			}
		}
		if len(values) > 0 {
			obj[pair[1]] = values
		}
	}
	b, _ := json.Marshal(obj)
	var r request
	err := json.Unmarshal(b, &r)
	return r, err
}
func queryCode(code string) string {
	switch code {
	case "QueueDoesNotExist":
		return "AWS.SimpleQueueService.NonExistentQueue"
	case "QueueNameExists":
		return "QueueAlreadyExists"
	case "EmptyBatchRequest", "BatchEntryIdsNotDistinct", "TooManyEntriesInBatchRequest", "BatchRequestTooLong", "InvalidBatchEntryId", "PurgeQueueInProgress":
		return "AWS.SimpleQueueService." + code
	}
	return code
}
func writeError(w http.ResponseWriter, query bool, e *serviceError) {
	if !query {
		w.Header().Set("Content-Type", "application/x-amz-json-1.0")
		w.Header().Set("x-amzn-ErrorType", "com.amazonaws.sqs#"+e.Code)
		w.Header().Set("x-amzn-query-error", queryCode(e.Code)+";Sender")
		w.WriteHeader(e.Status)
		_ = json.NewEncoder(w).Encode(map[string]string{"__type": "com.amazonaws.sqs#" + e.Code, "message": e.Message})
		return
	}
	w.Header().Set("Content-Type", "text/xml")
	w.WriteHeader(e.Status)
	enc := xml.NewEncoder(w)
	start := xml.StartElement{Name: xml.Name{Local: "ErrorResponse"}}
	_ = enc.EncodeToken(start)
	encodeElement(enc, "Error", map[string]any{"Type": "Sender", "Code": queryCode(e.Code), "Message": e.Message}, "")
	encodeElement(enc, "RequestId", w.Header().Get("x-amzn-RequestId"), "")
	_ = enc.EncodeToken(start.End())
	_ = enc.Flush()
}
func writeQuery(w http.ResponseWriter, op string, out map[string]any) {
	w.Header().Set("Content-Type", "text/xml")
	enc := xml.NewEncoder(w)
	root := xml.StartElement{Name: xml.Name{Local: op + "Response"}, Attr: []xml.Attr{{Name: xml.Name{Local: "xmlns"}, Value: "http://queue.amazonaws.com/doc/2012-11-05/"}}}
	_ = enc.EncodeToken(root)
	// Normalize typed maps/slices to the JSON data model before XML encoding.
	b, _ := json.Marshal(out)
	var normalized map[string]any
	_ = json.Unmarshal(b, &normalized)
	if len(normalized) > 0 {
		encodeElement(enc, op+"Result", normalized, op)
	}
	encodeElement(enc, "ResponseMetadata", map[string]any{"RequestId": w.Header().Get("x-amzn-RequestId")}, op)
	_ = enc.EncodeToken(root.End())
	_ = enc.Flush()
}
func encodeElement(enc *xml.Encoder, name string, value any, op string) {
	if values, ok := value.([]any); ok {
		item := map[string]string{"Messages": "Message", "QueueUrls": "QueueUrl", "queueUrls": "QueueUrl", "Successful": op + "ResultEntry", "Failed": "BatchResultErrorEntry"}[name]
		if item == "" {
			item = name
		}
		for _, v := range values {
			encodeElement(enc, item, v, op)
		}
		return
	}
	if values, ok := value.(map[string]any); ok && (name == "Attributes" || name == "MessageAttributes" || name == "Tags") {
		item, keyName := map[string]string{"Attributes": "Attribute", "MessageAttributes": "MessageAttribute", "Tags": "Tag"}[name], "Name"
		if name == "Tags" {
			keyName = "Key"
		}
		keys := sortedKeys(values)
		for _, k := range keys {
			encodeElement(enc, item, map[string]any{keyName: k, "Value": values[k]}, op)
		}
		return
	}
	start := xml.StartElement{Name: xml.Name{Local: name}}
	_ = enc.EncodeToken(start)
	if values, ok := value.(map[string]any); ok {
		for _, k := range sortedKeys(values) {
			encodeElement(enc, k, values[k], op)
		}
	} else if value != nil {
		_ = enc.EncodeToken(xml.CharData(fmt.Sprint(value)))
	}
	_ = enc.EncodeToken(start.End())
}
func sortedKeys(v map[string]any) []string {
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
