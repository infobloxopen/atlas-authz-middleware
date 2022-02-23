// package opa_client builds a REST client that opa should already exist
package opa_client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"syscall"

	"github.com/open-policy-agent/opa/server/types"
	"golang.org/x/net/http/httpguts"
	"google.golang.org/grpc/metadata"
)

const (
	DefaultAddress = "http://localhost:8181"
	contentType    = "application/json"
)

var (
	ErrUndefined = errors.New("undefined decision")
)

// Client implements the Clienter interface
type Client struct {
	cli     *http.Client
	address string
}

// Clienter is the opa client interface
//
// FIXME: this interface is incomplete and may change
// implement at your own discretion
type Clienter interface {
	Address() string
	CustomQueryStream(ctx context.Context, document string, postReqBody []byte, respRdrFn StreamReaderFn) error
	CustomQueryBytes(ctx context.Context, document string, reqData interface{}) ([]byte, error)
	CustomQuery(ctx context.Context, document string, reqData, resp interface{}) error
	Health() error
	Query(ctx context.Context, reqData, resp interface{}) error
}

type Option func(c *Client)

func New(address string, opts ...Option) Clienter {

	c := &Client{
		cli:     http.DefaultClient,
		address: address,
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// WithHTTPClient overrides the default http.Client to call Opa
func WithHTTPClient(cli *http.Client) Option {
	return func(c *Client) {
		if cli != nil {
			c.cli = cli
		}
	}
}

// do handles errors connecting to OPA
func (c *Client) do(req *http.Request) (*http.Response, error) {
	resp, err := c.cli.Do(req)

	// Check for connection refused errors
	if errors.Is(err, syscall.ECONNREFUSED) {
		return resp, NewErrorV1(http.StatusText(http.StatusServiceUnavailable), err)
	}

	return resp, err
}

// String implements fmt.Stringer interface
func (c Client) String() string {
	return fmt.Sprintf(`opa_client.Client{address:"%s"}`, c.address)
}

// Address retrieves the protocol://address of server
func (c *Client) Address() string {
	return fmt.Sprintf("%s", c.address)
}

func (c *Client) Health() error {
	ref := fmt.Sprintf("%s/health", c.Address())
	req, err := http.NewRequest("GET", ref, nil)
	if err != nil {
		return err
	}
	_, err = c.do(req)
	return err
}

// Query requests evaluation of reqData against the default document: /data/system/main
// See CustomQuery
func (c *Client) Query(ctx context.Context, reqData, resp interface{}) error {
	return c.CustomQuery(ctx, "", reqData, resp)
}

// StreamReaderFn defines fn that accepts io.Reader parameter
type StreamReaderFn func(io.Reader) error

// CustomQueryStream requests evaluation at a document of the caller's choice
// StreamReaderFn is supplied to directly read/parse from non-error OPA response stream.
//
// https://www.openpolicyagent.org/docs/latest/rest-api/#query-api
func (c *Client) CustomQueryStream(ctx context.Context, document string, postReqBody []byte, respRdrFn StreamReaderFn) error {
	ref := fmt.Sprintf("%s/%s", c.Address(), document)

	req, err := http.NewRequest("POST", ref, bytes.NewBuffer(postReqBody))
	if err != nil {
		return err
	}

	md, _ := metadata.FromIncomingContext(ctx)
	for key := range md {
		val := md.Get(key)
		for _, v := range val {
			if checkHeader(req.URL.Scheme, key, v) {
				req.Header.Add(key, v)
			}
		}
	}

	req.Header.Set("Content-Type", contentType)

	postResp, err := c.do(req)
	if err != nil {
		return err
	}
	defer postResp.Body.Close()

	// Successful code, decode as document
	if postResp.StatusCode >= 200 && postResp.StatusCode < 400 {
		if respRdrFn != nil {
			err = respRdrFn(postResp.Body)
		}
		return err
	}

	bs, err := ioutil.ReadAll(postResp.Body)
	if err != nil {
		return err
	}
	buf := bytes.NewBuffer(bs)
	copy := buf.String()
	dec := json.NewDecoder(buf)

	// unsuccessful code, attempt to decode as types.ErrorV1
	var opaErrV1 types.ErrorV1
	if err := dec.Decode(&opaErrV1); err != nil {
		return fmt.Errorf("unparseable error from OPA %d: %s", postResp.StatusCode, copy)
	}

	return &opaErrV1
}

// CustomQueryBytes requests evaluation at a document of the caller's choice
// If non-error OPA response, returns OPA response bytes.
func (c *Client) CustomQueryBytes(ctx context.Context, document string, reqData interface{}) ([]byte, error) {
	postReqBody, err := json.Marshal(reqData)
	if err != nil {
		return nil, err
	}

	var bs []byte
	respRdrFn := func(rdr io.Reader) error {
		allBytes, err := ioutil.ReadAll(rdr)
		if err == nil {
			bs = allBytes
		}
		return err
	}

	err = c.CustomQueryStream(ctx, document, postReqBody, respRdrFn)
	if err != nil {
		return nil, err
	}

	return bs, nil
}

// CustomQuery requests evaluation at a document of the caller's choice
// A non-error OPA response is decoded into resp.
func (c *Client) CustomQuery(ctx context.Context, document string, reqData, resp interface{}) error {
	postReqBody, err := json.Marshal(reqData)
	if err != nil {
		return err
	}

	respRdrFn := func(rdr io.Reader) error {
		dec := json.NewDecoder(rdr)
		return dec.Decode(resp)
	}

	return c.CustomQueryStream(ctx, document, postReqBody, respRdrFn)
}

// https://github.com/golang/go/blob/master/src/net/http/transport.go#L498
func checkHeader(scheme, key, val string) bool {
	isHTTP := scheme == "http" || scheme == "https"
	if !isHTTP {
		return true
	}

	return httpguts.ValidHeaderFieldName(key) && httpguts.ValidHeaderFieldValue(val)
}

// UploadRegoPolicy creates/updates an OPA policy.
// Intended for unit-testing.
//
// https://www.openpolicyagent.org/docs/latest/rest-api/#create-or-update-a-policy
func (c *Client) UploadRegoPolicy(ctx context.Context, policyID string, policyRego []byte, resp interface{}) error {

	ref := fmt.Sprintf("%s/v1/policies/%s", c.Address(), policyID)

	req, err := http.NewRequest("PUT", ref, bytes.NewBuffer(policyRego))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "text/plain")

	putResp, err := c.do(req)
	if err != nil {
		return err
	}
	defer putResp.Body.Close()
	bs, _ := ioutil.ReadAll(putResp.Body)

	buf := bytes.NewBuffer(bs)
	copy := buf.String()
	dec := json.NewDecoder(buf)

	// Successful code, decode as document
	if putResp.StatusCode >= 200 && putResp.StatusCode < 400 {
		if resp == nil {
			return nil
		}
		return dec.Decode(resp)
	}

	// unsuccessful code, attempt to decode as types.ErrorV1
	var opaErrV1 types.ErrorV1
	if err := dec.Decode(&opaErrV1); err != nil {
		return fmt.Errorf("unparseable error from OPA: StatusCode=%d: `%s`", putResp.StatusCode, copy)
	}

	return &opaErrV1
}
