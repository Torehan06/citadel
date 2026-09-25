package sqs

import "strings"

func (h *Handler) batch(c *call, op string, r *request) (map[string]any, error) {
	if _, err := loadQueue(h.st.DB(), c, r.QueueUrl); err != nil {
		return nil, err
	}
	if len(r.Entries) == 0 {
		return nil, fail("EmptyBatchRequest", "There should be at least one %sRequestEntry in the request.", op)
	}
	if len(r.Entries) > 10 {
		return nil, fail("TooManyEntriesInBatchRequest", "Maximum number of entries per request are 10. You have sent %d.", len(r.Entries))
	}
	seen := map[string]bool{}
	size := 0
	for _, entry := range r.Entries {
		if !queueNameRE.MatchString(entry.Id) {
			return nil, fail("InvalidBatchEntryId", "A batch entry id can only contain alphanumeric characters, hyphens and underscores. It can be at most 80 letters long.")
		}
		if seen[entry.Id] {
			return nil, fail("BatchEntryIdsNotDistinct", "Id %s repeated.", entry.Id)
		}
		seen[entry.Id] = true
		size += len(entry.MessageBody)
		for name, a := range entry.MessageAttributes {
			size += len(name) + len(a.DataType) + len(a.StringValue) + len(a.BinaryValue)
		}
	}
	if size > 1048576 {
		return nil, fail("BatchRequestTooLong", "Batch requests cannot be longer than 1048576 bytes. You have sent %d bytes.", size)
	}
	success := []map[string]any{}
	failed := []map[string]any{}
	for _, entry := range r.Entries {
		entry.QueueUrl = r.QueueUrl
		var result map[string]any
		var err error
		if op == "SendMessageBatch" {
			result, err = h.sendMessage(c, &entry)
		} else {
			result, err = h.receiptOperation(c, strings.TrimSuffix(op, "Batch"), &entry)
		}
		if err != nil {
			e := asError(err)
			failed = append(failed, map[string]any{"Id": entry.Id, "SenderFault": e.Status < 500, "Code": queryCode(e.Code), "Message": e.Message})
		} else {
			result["Id"] = entry.Id
			success = append(success, result)
		}
	}
	return map[string]any{"Successful": success, "Failed": failed}, nil
}
