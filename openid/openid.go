// Copyright 2016 Canonical Ltd.
// Licensed under the LGPLv3, see LICENSE file for details.

// Package openid contains functions to help log-in to Ubuntu SSO using
// OpenID 2.0.
package openid

import (
	"net/url"
	"strings"

	"github.com/yohcop/openid-go"
	"gopkg.in/errgo.v1"

	"github.com/juju/usso"
)

const (
	// These standard simple registration fields are supported by
	// Ubuntu SSO.
	SRegNickname = "nickname"
	SRegEmail    = "email"
	SRegFullName = "fullname"
	SRegPostcode = "postcode"
	SRegCountry  = "country"
	SRegLanguage = "language"
	SRegTimezone = "timezone"

	// These non-standard simple registration fields are supported by
	// Ubuntu SSO.
	SRegAddress1 = "x_address1"
	SRegAddress2 = "x_address2"
	SRegCity     = "x_city"
	SRegProvince = "x_province"
	SRegPhone    = "x_phone"
)

const (
	nsSReg  = "http://openid.net/extensions/sreg/1.1"
	nsTeams = "http://ns.launchpad.net/2007/openid-teams"
)

var (
	// ErrCancel is the error cause returned by Client.Verify when a
	// login request has been cancelled.
	ErrCancel = errgo.New("login cancelled")
)

// OpenIDError represents an error response from an OpenID server. See
// http://openid.net/specs/openid-authentication-2_0.html#rfc.section.5.2.3
// for details.
type OpenIDError struct {
	// Message contains the "openid.error" field from the response.
	Message string

	// Contact contains the "openid.contact" field from the response.
	Contact string

	// Reference contains the "openid.reference" field from the
	// response.
	Reference string
}

// Error implements error.Error.
func (e *OpenIDError) Error() string {
	return e.Message
}

// NonceStore is the NonceStore type from github.com/yohcop/openid-go. It
// is replicated here for the convenience of clients.
type NonceStore interface {
	openid.NonceStore
}

// DiscoveryCache is the DiscoveryCache type from
// github.com/yohcop/openid-go. It is replicated here for the convenience
// of clients.
type DiscoveryCache interface {
	openid.DiscoveryCache
}

// Client is an OpenID client that provides OpenID login for a specific
// Ubuntu SSO server.
type Client struct {
	// Server holds the Ubuntu SSO server that OpenID requests will
	// be made against.
	Server usso.UbuntuSSOServer

	// NonceStore contains the NonceStore used to verify the OpenID
	// responses have not been previously processed.
	NonceStore NonceStore

	// DiscoveryCache contains a DiscoveryCache to use when verifying
	// OpenID responses.
	DiscoveryCache DiscoveryCache
}

// NewClient creates a new Client for the specified Ubuntu SSO server. If
// ns is nil then a new in-memory NonceStore will be created. If dc is
// nil then a DiscoveryCache derived from the server wil be used.
func NewClient(s usso.UbuntuSSOServer, ns NonceStore, dc DiscoveryCache) *Client {
	if ns == nil {
		ns = openid.NewSimpleNonceStore()
	}
	if dc == nil {
		dc = ussoDiscoveryCache{s}
	}
	return &Client{
		Server:         s,
		NonceStore:     ns,
		DiscoveryCache: dc,
	}
}

// Request contains the paramaters for an UbuntuSSO OpenID login request.
type Request struct {
	// ReturnTo contains the callback address for the service, this is
	// where the login response will come.
	ReturnTo string

	// Realm contains the realm that the user is logging into. See
	// http://openid.net/specs/openid-authentication-2_0.html#realms
	// for details.
	Realm string

	// Teams contains a list of launchpad teams to query membership
	// of for the logged in user.
	Teams []string

	// SRegRequired contains a list of simple registration fields
	// that are required by the service.
	SRegRequired []string

	// SRegOptional contains a list of simple registration fields
	// that are optional, but requested by the service.
	SRegOptional []string
}

// RedirectURL creates an OpenID login request addressed to c.Server.
func (c *Client) RedirectURL(r *Request) string {
	v := url.Values{
		"openid.ns":         {"http://specs.openid.net/auth/2.0"},
		"openid.mode":       {"checkid_setup"},
		"openid.claimed_id": {"http://specs.openid.net/auth/2.0/identifier_select"},
		"openid.identity":   {"http://specs.openid.net/auth/2.0/identifier_select"},
		"openid.return_to":  {r.ReturnTo},
	}
	if r.Realm != "" {
		v.Set("openid.realm", r.Realm)
	}
	if len(r.Teams) > 0 {
		v.Set("openid.ns.lp", nsTeams)
		v.Set("openid.lp.query_membership", strings.Join(r.Teams, ","))
	}
	if len(r.SRegRequired) > 0 {
		v.Set("openid.ns.sreg", nsSReg)
		v.Set("openid.sreg.required", strings.Join(r.SRegRequired, ","))
	}
	if len(r.SRegOptional) > 0 {
		v.Set("openid.ns.sreg", nsSReg)
		v.Set("openid.sreg.optional", strings.Join(r.SRegOptional, ","))
	}
	return c.Server.OpenIDURL() + "?" + v.Encode()
}

// Response contains the values returned from Ubuntu SSO after a
// successful login.
type Response struct {
	// ID contains the claimed_id of the logged in user. This will
	// always be present in a successful login.
	ID string

	// Teams contains any launchpad teams that were specified in the
	// OpenID response.
	Teams []string

	// SReg contains any simple registration fields are
	// were provided in the OpenID response.
	SReg map[string]string
}

// verify is used to perform the OpenID verification of the login
// response. This is declared as a variable so it can be overridden for
// testing.
var verify = openid.Verify

// Verify processes a positive assertion from Ubuntu SSO. If the
// verification is successful any parameters asserted by Ubuntu SSO will
// be set in the Response. If the OpenID response reports that the login
// was cancelled then an error will be returned with a cause of
// ErrCancel. If the OpenID response reports an error occurred then an
// error of type *OpenIDError will be returned.
func (c *Client) Verify(requestURL string) (*Response, error) {
	u, err := url.ParseRequestURI(requestURL)
	if err != nil {
		return nil, err
	}
	v := u.Query()
	switch mode := v.Get("openid.mode"); mode {
	case "error":
		return nil, &OpenIDError{
			Message:   v.Get("openid.error"),
			Contact:   v.Get("openid.contact"),
			Reference: v.Get("openid.reference"),
		}
	case "cancel":
		return nil, ErrCancel
	default:
		return nil, errgo.Newf("unrecognised mode %q", mode)
	case "id_res":
	}
	if endpoint := v.Get("openid.op_endpoint"); endpoint != c.Server.OpenIDURL() {
		return nil, errgo.Newf("OpenID response from unexpected endpoint %q", endpoint)
	}

	// Verify the openid response.
	id, err := verify(requestURL, c.DiscoveryCache, c.NonceStore)
	if err != nil {
		return nil, err
	}
	r := Response{
		ID: id,
	}
	// check for extensions in the response.
	signed := strings.Split(v.Get("openid.signed"), ",")
	if v.Get("openid.ns.lp") == nsTeams && contains(signed, "lp.is_member") {
		r.Teams = strings.Split(v.Get("openid.lp.is_member"), ",")
	}
	if v.Get("openid.ns.sreg") == nsSReg {
		for k := range v {
			if !strings.HasPrefix(k, "openid.sreg.") {
				continue
			}
			if !contains(signed, k[len("openid."):]) {
				continue
			}
			if r.SReg == nil {
				r.SReg = make(map[string]string)
			}
			r.SReg[k[len("openid.sreg."):]] = v.Get(k)
		}
	}
	return &r, nil
}

// contains finds whether ss contains s.
func contains(ss []string, s string) bool {
	for _, t := range ss {
		if t == s {
			return true
		}
	}
	return false
}

// ussoDiscoveryCache is a DiscoveryCache that generates the cached
// information based on the behaviour of Ubuntu SSO.
type ussoDiscoveryCache struct {
	server usso.UbuntuSSOServer
}

// Put implements DiscoveryCache.Put, it does nothing.
func (dc ussoDiscoveryCache) Put(id string, info openid.DiscoveredInfo) {
}

// Get implements DiscoveryCache.Get by returning Ubuntu SSO specific
// values when the id has a prefix matching the Ubuntu SSO server's login
// URL. The generated data uses id as both the local ID and the claimed
// ID, and the server's OpenID endpoint.
func (dc ussoDiscoveryCache) Get(id string) openid.DiscoveredInfo {
	if !strings.HasPrefix(id, dc.server.LoginURL()) {
		return nil
	}
	return discoveredInfo{
		id:       id,
		endpoint: dc.server.OpenIDURL(),
	}
}

type discoveredInfo struct {
	id       string
	endpoint string
}

func (d discoveredInfo) OpEndpoint() string {
	return d.endpoint
}

func (d discoveredInfo) OpLocalID() string {
	return d.id
}

func (d discoveredInfo) ClaimedID() string {
	return d.id
}
