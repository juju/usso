package usso

import (
	"launchpad.net/gocheck"
	"net/url"
)

// No need to touch anything.
func (suite *USSOTestSuite) TestNormalizeURLReturnsBasicURL(c *gocheck.C) {
	output, err := NormalizeURL("http://example.com/path")
	c.Check(err, gocheck.Equals, nil)
	c.Check(output, gocheck.Equals, "http://example.com/path")
}

// Remove the port 80.
func (suite *USSOTestSuite) TestNormalizeURLStripsStandardHTTPPort(
	c *gocheck.C) {
	output, err := NormalizeURL("http://example.com:80/path")
	c.Check(err, gocheck.Equals, nil)
	c.Check(output, gocheck.Equals, "http://example.com/path")
}

// Remove the port 443.
func (suite *USSOTestSuite) TestNormalizeURLStripsStandardHTTPSPort(
	c *gocheck.C) {
	output, err := NormalizeURL("https://example.com:443/path")
	c.Check(err, gocheck.Equals, nil)
	c.Check(output, gocheck.Equals, "https://example.com/path")
}

// Leave non standard port where it is.
func (suite *USSOTestSuite) TestNormalizeURLLeavesNonstandardPort(
	c *gocheck.C) {
	output, err := NormalizeURL("http://example.com:8080/")
	c.Check(err, gocheck.Equals, nil)
	c.Check(output, gocheck.Equals, "http://example.com:8080/")
}

// Remove query string.
func (suite *USSOTestSuite) TestNormalizeURLStripsParameters(c *gocheck.C) {
	output, err := NormalizeURL("http://example.com/path?query=value&param=arg")
	c.Check(err, gocheck.Equals, nil)
	c.Check(output, gocheck.Equals, "http://example.com/path")
}

// Parse one key/value parameter correctly.
func (suite *USSOTestSuite) TestNormalizeParametersReturnsParameters(
	c *gocheck.C) {
	output, err := NormalizeParameters(url.Values{"param": []string{"value"}})
	c.Check(err, gocheck.Equals, nil)
	c.Check(output, gocheck.Equals, "param=value")
}

// Parse key/value parameters correctly, note the order of the pairs can vary.
func (suite *USSOTestSuite) TestNormalizeParametersConcatenatesParameters(
	c *gocheck.C) {
	output, err := NormalizeParameters(
		url.Values{"a": []string{"1"}, "b": []string{"2"}})
	c.Check(err, gocheck.Equals, nil)
	c.Check(output, gocheck.Matches, "(a=1&b=2|b=2&a=1)")
}

// Escapes the parameters correctly.
func (suite *USSOTestSuite) TestNormalizeParametersEscapesParameters(
	c *gocheck.C) {
	output, err := NormalizeParameters(url.Values{"a&b": []string{"1"}})
	c.Check(err, gocheck.Equals, nil)
	c.Check(output, gocheck.Equals, "a%26b=1")
}

// oauth_signature could appear in the query string but has to be removed
// from the normalized parameter.
func (suite *USSOTestSuite) TestNormalizeParametersOmitsOAuthSignature(
	c *gocheck.C) {
	params := url.Values{
		"a":               []string{"1"},
		"oauth_signature": []string{"foobarsplatszot"},
		"z":               []string{"26"},
	}
	output, err := NormalizeParameters(params)
	c.Check(err, gocheck.Equals, nil)
	c.Check(output, gocheck.Matches, "(a=1&z=26|z=26&a=1)")
}
