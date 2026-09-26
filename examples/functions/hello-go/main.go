// Command hello-go is a Citadel Lambda function: a WASI preview 1 command
// module that reads its event from stdin, writes its response to stdout and
// logs to stderr.
//
//	GOOS=wasip1 GOARCH=wasm go build -o bootstrap.wasm .
//	zip function.zip bootstrap.wasm
//	aws lambda create-function --function-name hello --runtime provided.al2023 \
//	    --handler bootstrap --role arn:aws:iam::123456789012:role/lambda \
//	    --zip-file fileb://function.zip
//
// Events:
//   - {"name": "Ada"}            answers {"message": "Hello, Ada!"}
//   - {"Records": [...]}         (SQS, S3) logs each record, answers {"processed": n}
//   - {"fail": "why"}            reports an error: prints {"errorType", "errorMessage"}, exits 1
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

type event struct {
	Name    string            `json:"name"`
	Fail    string            `json:"fail"`
	Records []json.RawMessage `json:"Records"`
}

func main() {
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		fail("Runtime.ReadError", err.Error())
	}
	var ev event
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &ev); err != nil {
			fail("InvalidEvent", err.Error())
		}
	}
	fmt.Fprintf(os.Stderr, "hello-go: %s version %s got %d bytes\n",
		os.Getenv("AWS_LAMBDA_FUNCTION_NAME"), os.Getenv("AWS_LAMBDA_FUNCTION_VERSION"), len(raw))
	switch {
	case ev.Fail != "":
		fail("HelloError", ev.Fail)
	case ev.Records != nil:
		for _, r := range ev.Records {
			var rec struct {
				Body      string `json:"body"`
				EventName string `json:"eventName"`
				S3        struct {
					Object struct {
						Key string `json:"key"`
					} `json:"object"`
				} `json:"s3"`
			}
			_ = json.Unmarshal(r, &rec)
			switch {
			case rec.EventName != "":
				fmt.Fprintf(os.Stderr, "record: %s %s\n", rec.EventName, rec.S3.Object.Key)
			default:
				fmt.Fprintf(os.Stderr, "record: %s\n", rec.Body)
			}
		}
		respond(map[string]int{"processed": len(ev.Records)})
	default:
		name := ev.Name
		if name == "" {
			name = "world"
		}
		respond(map[string]string{"message": "Hello, " + name + "!"})
	}
}

func respond(v any) {
	if err := json.NewEncoder(os.Stdout).Encode(v); err != nil {
		os.Exit(1)
	}
}

// fail reports a function error the way Citadel's runtime expects: an error
// object on stdout and a non-zero exit.
func fail(typ, msg string) {
	_ = json.NewEncoder(os.Stdout).Encode(map[string]string{"errorType": typ, "errorMessage": msg})
	os.Exit(1)
}
