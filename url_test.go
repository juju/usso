package usso

import (
	"launchpad.net/gocheck"
)


func (suite *USSOTestSuite) TestNormalizeMethod(c *gocheck.C) {
	c.Assert(NormalizeMethod("http://example.com/path?query=params"), gocheck.Equals, "HTTP")
	c.Assert(NormalizeMethod("https://example.com/path?query=params"), gocheck.Equals, "HTTPS")
}


func (suite *USSOTestSuite) TestNormalizeURLReturnsBasicURL(c *gocheck.C) {
	c.Assert(NormalizeURL("http://example.com/path"), gocheck.Equals, "http://example.com/path")
}


func (suite *USSOTestSuite) TestNormalizeURLStripsStandardPort(c *gocheck.C) {
	c.Assert(NormalizeURL("http://example.com:80/"), gocheck.Equals, "http://example.com/path")
	c.Assert(NormalizeURL("https://example.com:443/"), gocheck.Equals, "https://example.com/path")
}


func (suite *USSOTestSuite) TestNormalizeURLLeavesNonstandardPort(c *gocheck.C) {
	c.Assert(NormalizeURL("http://example.com:8080/"), gocheck.Equals, "http://example.com/path")
}


func (suite *USSOTestSuite) TestNormalizeURLStripsParameters(c *gocheck.C) {
	c.Assert(NormalizeURL("http://example.com/path?query=value&param=arg"), gocheck.Equals, "http://example.com/path")
}


func (suite *USSOTestSuite) TestNormalizeParametersReturnsParameters(c *gocheck.C) {
	c.Assert(NormalizeParameters(map[string]string{"param": "value"}), gocheck.Equals, "param=value")
}


func (suite *USSOTestSuite) TestNormalizeParametersConcatenatesParameters(c *gocheck.C) {
	c.Assert(NormalizeParameters(map[string]string{"a": "1", "b": "2"}), gocheck.Equals, "a=1&b=2")
}


func (suite *USSOTestSuite) TestNormalizeParametersSortsParameters(c *gocheck.C) {
	params := map[string]string{
		"b": "x",
		"a": "y",
		"c": "z",
	}
	c.Assert(NormalizeParameters(params), gocheck.Equals, "a=y&b=x&c=z")
}


func (suite *USSOTestSuite) TestNormalizeParametersEscapesParameters(c *gocheck.C) {
	c.Assert(nil, gocheck.Equals, "TEST THIS")
}


func (suite *USSOTestSuite) TestNormalizeParametersOmitsOAuthSignature(c *gocheck.C) {
	c.Assert(nil, gocheck.Equals, "TEST THIS")
}
