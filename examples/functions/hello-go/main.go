// hello-go is the smallest Citadel function. Citadel runs it as a WASI
// command module: the event arrives on stdin, the response goes to stdout,
// and anything written to stderr lands in the function's log stream.
//
// Build it with ./build.sh (GOOS=wasip1 GOARCH=wasm), which produces
// function.zip containing bootstrap.wasm.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

type event struct {
	Name    string `json:"name"`
	Records []struct {
		Body        string `json:"body"`
		EventSource string `json:"eventSource"`
		S3          *struct {
			Bucket struct{ Name string } `json:"bucket"`
			Object struct{ Key string }  `json:"object"`
		} `json:"s3"`
	} `json:"Records"`
}

func main() {
	var e event
	if err := json.NewDecoder(os.Stdin).Decode(&e); err != nil && err != io.EOF {
		fail("bad event: " + err.Error())
	}
	name := e.Name
	if name == "" {
		name = "world"
	}
	for _, r := range e.Records {
		switch {
		case r.S3 != nil:
			fmt.Fprintf(os.Stderr, "hello-go: object %s/%s\n", r.S3.Bucket.Name, r.S3.Object.Key)
		default:
			fmt.Fprintf(os.Stderr, "hello-go: %s message %q\n", r.EventSource, r.Body)
		}
	}
	fmt.Fprintf(os.Stderr, "hello-go: greeting %s (function %s)\n", name, os.Getenv("AWS_LAMBDA_FUNCTION_NAME"))
	out := map[string]any{"message": "Hello, " + name + "!"}
	if len(e.Records) > 0 {
		out["records"] = len(e.Records)
	}
	_ = json.NewEncoder(os.Stdout).Encode(out)
}

// fail reports an error the way Lambda runtimes do: an error object on
// stdout and a non-zero exit.
func fail(msg string) {
	_ = json.NewEncoder(os.Stdout).Encode(map[string]string{"errorType": "HandlerError", "errorMessage": msg})
	os.Exit(1)
}
