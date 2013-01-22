package usso

import (
	"launchpad.net/gocheck"
	"net/url"
)

func (suite *USSOTestSuite) TestNormalizeURLReturnsBasicURL(c *gocheck.C) {
	output, err := NormalizeURL("http://example.com/path")
	c.Check(err, gocheck.Equals, nil)
	c.Check(output, gocheck.Equals, "http://example.com/path")
}

func (suite *USSOTestSuite) TestNormalizeURLStripsStandardHTTPPort(
	c *gocheck.C) {
	output, err := NormalizeURL("http://example.com:80/path")
	c.Check(err, gocheck.Equals, nil)
	c.Check(output, gocheck.Equals, "http://example.com/path")
}

func (suite *USSOTestSuite) TestNormalizeURLStripsStandardHTTPSPort(
	c *gocheck.C) {
	output, err := NormalizeURL("https://example.com:443/path")
	c.Check(err, gocheck.Equals, nil)
	c.Check(output, gocheck.Equals, "https://example.com/path")
}

func (suite *USSOTestSuite) TestNormalizeURLLeavesNonstandardPort(
	c *gocheck.C) {
	output, err := NormalizeURL("http://example.com:8080/")
	c.Check(err, gocheck.Equals, nil)
	c.Check(output, gocheck.Equals, "http://example.com:8080/")
}

func (suite *USSOTestSuite) TestNormalizeURLStripsParameters(c *gocheck.C) {
	output, err := NormalizeURL("http://example.com/path?query=value&param=arg")
	c.Check(err, gocheck.Equals, nil)
	c.Check(output, gocheck.Equals, "http://example.com/path")
}

func (suite *USSOTestSuite) TestNormalizeParametersReturnsParameters(
	c *gocheck.C) {
	output, err := NormalizeParameters(url.Values{"param": []string{"value"}})
	c.Check(err, gocheck.Equals, nil)
	c.Check(output, gocheck.Equals, "param=value")
}

func (suite *USSOTestSuite) TestNormalizeParametersConcatenatesParameters(
	c *gocheck.C) {
	output, err := NormalizeParameters(
		url.Values{"a": []string{"1"}, "b": []string{"2"}})
	c.Check(err, gocheck.Equals, nil)
	c.Check(output, gocheck.Matches, "(a=1&b=2|b=2&a=1)")
}

func (suite *USSOTestSuite) TestNormalizeParametersSortsParameters(
	c *gocheck.C) {
	params := url.Values{
		"b": []string{"x"},
		"a": []string{"y"},
	}
	output, err := NormalizeParameters(params)
	c.Check(err, gocheck.Equals, nil)
	c.Check(output, gocheck.Matches, "(a=y&b=x|b=x&a=y)")
}

func (suite *USSOTestSuite) TestNormalizeParametersEscapesParameters(
	c *gocheck.C) {
	output, err := NormalizeParameters(url.Values{"a&b": []string{"1"}})
	c.Check(err, gocheck.Equals, nil)
	c.Check(output, gocheck.Equals, "a%26b=1")
}

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
