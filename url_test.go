package usso

import (
	"launchpad.net/gocheck"
	"net/url"
)

// When NormalizeURL() is passed a simple URL, it will make no changes
// to it.
func (suite *USSOTestSuite) TestNormalizeURLReturnsBasicURL(c *gocheck.C) {
	output, err := NormalizeURL("http://example.com/path")
	c.Check(err, gocheck.Equals, nil)
	c.Check(output, gocheck.Equals, "http://example.com/path")
}

// NormalizeURL() strips the ":80" from http:// URLs that contain it.
func (suite *USSOTestSuite) TestNormalizeURLStripsStandardHTTPPort(
	c *gocheck.C) {
	output, err := NormalizeURL("http://example.com:80/path")
	c.Check(err, gocheck.Equals, nil)
	c.Check(output, gocheck.Equals, "http://example.com/path")
}

// NormalizeURL() strips the ":443" from https:// URLs that contain it.
func (suite *USSOTestSuite) TestNormalizeURLStripsStandardHTTPSPort(
	c *gocheck.C) {
	output, err := NormalizeURL("https://example.com:443/path")
	c.Check(err, gocheck.Equals, nil)
	c.Check(output, gocheck.Equals, "https://example.com/path")
}

// NormalizeURL() does not remove non-standard ports from the URL.
func (suite *USSOTestSuite) TestNormalizeURLLeavesNonstandardPort(
	c *gocheck.C) {
	output, err := NormalizeURL("http://example.com:8080/")
	c.Check(err, gocheck.Equals, nil)
	c.Check(output, gocheck.Equals, "http://example.com:8080/")
}

// NormalizeURL() strips the query string from URLs.
func (suite *USSOTestSuite) TestNormalizeURLStripsParameters(c *gocheck.C) {
	output, err := NormalizeURL("http://example.com/path?query=value&param=arg")
	c.Check(err, gocheck.Equals, nil)
	c.Check(output, gocheck.Equals, "http://example.com/path")
}

// NormalizeParameters() takes a url.Values instance and returns an
// encoded key=value string containing the parameters in that instance.
func (suite *USSOTestSuite) TestNormalizeParametersReturnsParameters(
	c *gocheck.C) {
	output, err := NormalizeParameters(url.Values{"param": []string{"value"}})
	c.Check(err, gocheck.Equals, nil)
	c.Check(output, gocheck.Equals, "param=value")
}

// NormalizeParameters() encodes multiple key/value parameters as a
// query string.
func (suite *USSOTestSuite) TestNormalizeParametersConcatenatesParameters(
	c *gocheck.C) {
	output, err := NormalizeParameters(
		url.Values{"a": []string{"1"}, "b": []string{"2"}})
	c.Check(err, gocheck.Equals, nil)
	c.Check(output, gocheck.Matches, "(a=1&b=2)")
}

// NormalizeParameters() escapes the parameters correctly when encoding
// them as a query string.
func (suite *USSOTestSuite) TestNormalizeParametersEscapesParameters(
	c *gocheck.C) {
	output, err := NormalizeParameters(url.Values{"a&b": []string{"1"}})
	c.Check(err, gocheck.Equals, nil)
	c.Check(output, gocheck.Equals, "a%26b=1")
}

// If oauth_signature appears in the parameters passed to
// NormalizeParameters(), it is omitted in the returned string as it does not
// have to be included in the computation of the new oauth_signature.
func (suite *USSOTestSuite) TestNormalizeParametersOmitsOAuthSignature(
	c *gocheck.C) {
	params := url.Values{
		"a":               []string{"1"},
		"oauth_signature": []string{"foobarsplatszot"},
		"z":               []string{"26"},
	}
	output, err := NormalizeParameters(params)
	c.Check(err, gocheck.Equals, nil)
	c.Check(output, gocheck.Matches, "(a=1&z=26)")
}
