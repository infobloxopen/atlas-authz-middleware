// package opa_client builds a REST client that opa should already exist
package opa_client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	CustomQuery(ctx context.Context, document string, data interface{}, resp interface{}) error
	Health() error
	Query(ctx context.Context, data interface{}, resp interface{}) error
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

// Query requests evaluation of data against the default document: /data/system/main
// See CustomQuery
func (c *Client) Query(ctx context.Context, data, resp interface{}) error {
	return c.CustomQuery(ctx, "", data, resp)
}

// CustomQuery requests evaluation at a document of the caller's choice
//
// https://www.openpolicyagent.org/docs/latest/rest-api/#query-api
func (c *Client) CustomQuery(ctx context.Context, document string, data, resp interface{}) error {

	ref := fmt.Sprintf("%s/%s", c.Address(), document)

	bs, err := json.Marshal(data)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", ref, bytes.NewBuffer(bs))
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
	bs, _ = ioutil.ReadAll(postResp.Body)

	buf := bytes.NewBuffer(bs)
	copy := buf.String()
	dec := json.NewDecoder(buf)

	// Successful code, decode as document
	if postResp.StatusCode >= 200 && postResp.StatusCode < 400 {
		if resp == nil {
			return nil
		}
		return dec.Decode(resp)
	}

	// unsuccessful code, attempt to decode as types.ErrorV1
	var opaErrV1 types.ErrorV1
	if err := dec.Decode(&opaErrV1); err != nil {
		return fmt.Errorf("unparseable error from OPA %d: %s", postResp.StatusCode, copy)
	}

	return &opaErrV1
}

// https://github.com/golang/go/blob/master/src/net/http/transport.go#L498
func checkHeader(scheme, key, val string) bool {
	isHTTP := scheme == "http" || scheme == "https"
	if !isHTTP {
		return true
	}

	return httpguts.ValidHeaderFieldName(key) && httpguts.ValidHeaderFieldValue(val)
}
