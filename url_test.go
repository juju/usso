package usso

import (
	"launchpad.net/gocheck"
)


func (suite *USSOTestSuite) TestNormalizeMethodExtractsHTTP(c *gocheck.C) {
	output, err := NormalizeMethod("http://example.com/path?query=params")
	c.Assert(nil, gocheck.Equals, err)
	c.Assert(output, gocheck.Equals, "HTTP")
}


func (suite *USSOTestSuite) TestNormalizeMethodExtractsHTTPS(c *gocheck.C) {
	output, err := NormalizeMethod("https://example.com/path?query=params")
	c.Assert(nil, gocheck.Equals, err)
	c.Assert(output, gocheck.Equals, "HTTPS")
}


func (suite *USSOTestSuite) TestNormalizeURLReturnsBasicURL(c *gocheck.C) {
	output, err := NormalizeURL("http://example.com/path")
	c.Assert(nil, gocheck.Equals, err)
	c.Assert(output, gocheck.Equals, "http://example.com/path")
}


func (suite *USSOTestSuite) TestNormalizeURLStripsStandardHTTPPort(c *gocheck.C) {
	output, err := NormalizeURL("http://example.com:80/path")
	c.Assert(nil, gocheck.Equals, err)
	c.Assert(output, gocheck.Equals, "http://example.com/path")
}


func (suite *USSOTestSuite) TestNormalizeURLStripsStandardHTTPSPort(c *gocheck.C) {
	output, err := NormalizeURL("https://example.com:443/path")
	c.Assert(nil, gocheck.Equals, err)
	c.Assert(output, gocheck.Equals, "https://example.com/path")
}


func (suite *USSOTestSuite) TestNormalizeURLLeavesNonstandardPort(c *gocheck.C) {
	output, err := NormalizeURL("http://example.com:8080/")
	c.Assert(nil, gocheck.Equals, err)
	c.Assert(output, gocheck.Equals, "http://example.com:8080/")
}


func (suite *USSOTestSuite) TestNormalizeURLStripsParameters(c *gocheck.C) {
	output, err := NormalizeURL("http://example.com/path?query=value&param=arg")
	c.Assert(nil, gocheck.Equals, err)
	c.Assert(output, gocheck.Equals, "http://example.com/path")
}


func (suite *USSOTestSuite) TestNormalizeParametersReturnsParameters(c *gocheck.C) {
	output, err := NormalizeParameters(map[string]string{"param": "value"})
	c.Assert(nil, gocheck.Equals, err)
	c.Assert(output, gocheck.Equals, "param=value")
}


func (suite *USSOTestSuite) TestNormalizeParametersConcatenatesParameters(c *gocheck.C) {
	output, err := NormalizeParameters(map[string]string{"a": "1", "b": "2"})
	c.Assert(nil, gocheck.Equals, err)
	c.Assert(output, gocheck.Equals, "a=1&b=2")
}


func (suite *USSOTestSuite) TestNormalizeParametersSortsParameters(c *gocheck.C) {
	params := map[string]string{
		"b": "x",
		"a": "y",
		"c": "z",
	}
	output, err := NormalizeParameters(params)
	c.Assert(nil, gocheck.Equals, err)
	c.Assert(output, gocheck.Equals, "a=y&b=x&c=z")
}


func (suite *USSOTestSuite) TestNormalizeParametersEscapesParameters(c *gocheck.C) {
	output, err := NormalizeParameters(map[string]string{"a&b": "1"})
	c.Assert(nil, gocheck.Equals, err)
	c.Assert(output, gocheck.Equals, "a%26b=1")
}


func (suite *USSOTestSuite) TestNormalizeParametersOmitsOAuthSignature(c *gocheck.C) {
	params := map[string]string{
		"a": "1",
		"oauth_signature": "foobarsplatszot",
		"z": "26",
	}
	output, err := NormalizeParameters(params)
	c.Assert(nil, gocheck.Equals, err)
	c.Assert(output, gocheck.Equals, "a=1&z=26")
}
