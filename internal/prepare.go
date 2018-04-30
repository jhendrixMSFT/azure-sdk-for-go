package internal

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/url"
	"strings"

	"github.com/Azure/azure-pipeline-go/pipeline"
)

// CreateRequest creates a new pipeline.Request with the specified values.
func CreateRequest(method, baseURL, path string, pathParams map[string]string) (pipeline.Request, error) {
	for key, value := range pathParams {
		path = strings.Replace(path, "{"+key+"}", value, -1)
	}
	// TODO: check for extra / between elements
	path = baseURL + path
	u, err := url.Parse(path)
	if err != nil {
		return pipeline.Request{}, err
	}
	return pipeline.NewRequest(method, *u, nil)
}

// PathEscape escapes the string so it can be safely placed in a URL path.
func PathEscape(s string) string {
	return strings.Replace(url.QueryEscape(s), "+", "%20", -1)
}

// MarshalBodyAsJSON marshals v into JSON format and sets it as the request body.
func MarshalBodyAsJSON(req pipeline.Request, v interface{}) (pipeline.Request, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return req, err
	}
	return req, req.SetBody(bytes.NewReader(b))
}

// UnmarshalJSONBody unmarshals the response body into the value pointed to by v.
func UnmarshalJSONBody(resp pipeline.Response, v interface{}) error {
	defer resp.Response().Body.Close()
	b, err := ioutil.ReadAll(resp.Response().Body)
	if err != nil {
		return err
	}
	// some responses might include a BOM, remove for successful unmarshalling
	b = bytes.TrimPrefix(b, []byte("\xef\xbb\xbf"))
	return json.Unmarshal(b, v)
}
