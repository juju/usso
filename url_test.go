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

var escapeTests = map[string]string{
	"\x00": "%00",
	"\x01": "%01",
	"\x02": "%02",
	"\x03": "%03",
	"\x04": "%04",
	"\x05": "%05",
	"\x06": "%06",
	"\x07": "%07",
	"\x08": "%08",
	"\x09": "%09",
	"\x0a": "%0A",
	"\x0b": "%0B",
	"\x0c": "%0C",
	"\x0d": "%0D",
	"\x0e": "%0E",
	"\x0f": "%0F",
	"\x10": "%10",
	"\x11": "%11",
	"\x12": "%12",
	"\x13": "%13",
	"\x14": "%14",
	"\x15": "%15",
	"\x16": "%16",
	"\x17": "%17",
	"\x18": "%18",
	"\x19": "%19",
	"\x1a": "%1A",
	"\x1b": "%1B",
	"\x1c": "%1C",
	"\x1d": "%1D",
	"\x1e": "%1E",
	"\x1f": "%1F",
	"\x20": "%20",
	"\x21": "%21",
	"\x22": "%22",
	"\x23": "%23",
	"\x24": "%24",
	"\x25": "%25",
	"\x26": "%26",
	"\x27": "%27",
	"\x28": "%28",
	"\x29": "%29",
	"\x2a": "%2A",
	"\x2b": "%2B",
	"\x2c": "%2C",
	"\x2d": "-",
	"\x2e": ".",
	"\x2f": "%2F",
	"\x30": "0",
	"\x31": "1",
	"\x32": "2",
	"\x33": "3",
	"\x34": "4",
	"\x35": "5",
	"\x36": "6",
	"\x37": "7",
	"\x38": "8",
	"\x39": "9",
	"\x3a": "%3A",
	"\x3b": "%3B",
	"\x3c": "%3C",
	"\x3d": "%3D",
	"\x3e": "%3E",
	"\x3f": "%3F",
	"\x40": "%40",
	"\x41": "A",
	"\x42": "B",
	"\x43": "C",
	"\x44": "D",
	"\x45": "E",
	"\x46": "F",
	"\x47": "G",
	"\x48": "H",
	"\x49": "I",
	"\x4a": "J",
	"\x4b": "K",
	"\x4c": "L",
	"\x4d": "M",
	"\x4e": "N",
	"\x4f": "O",
	"\x50": "P",
	"\x51": "Q",
	"\x52": "R",
	"\x53": "S",
	"\x54": "T",
	"\x55": "U",
	"\x56": "V",
	"\x57": "W",
	"\x58": "X",
	"\x59": "Y",
	"\x5a": "Z",
	"\x5b": "%5B",
	"\x5c": "%5C",
	"\x5d": "%5D",
	"\x5e": "%5E",
	"\x5f": "_",
	"\x60": "%60",
	"\x61": "a",
	"\x62": "b",
	"\x63": "c",
	"\x64": "d",
	"\x65": "e",
	"\x66": "f",
	"\x67": "g",
	"\x68": "h",
	"\x69": "i",
	"\x6a": "j",
	"\x6b": "k",
	"\x6c": "l",
	"\x6d": "m",
	"\x6e": "n",
	"\x6f": "o",
	"\x70": "p",
	"\x71": "q",
	"\x72": "r",
	"\x73": "s",
	"\x74": "t",
	"\x75": "u",
	"\x76": "v",
	"\x77": "w",
	"\x78": "x",
	"\x79": "y",
	"\x7a": "z",
	"\x7b": "%7B",
	"\x7c": "%7C",
	"\x7d": "%7D",
	"\x7e": "~",
	"\x7f": "%7F",
	"\x80": "%80",
	"\x81": "%81",
	"\x82": "%82",
	"\x83": "%83",
	"\x84": "%84",
	"\x85": "%85",
	"\x86": "%86",
	"\x87": "%87",
	"\x88": "%88",
	"\x89": "%89",
	"\x8a": "%8A",
	"\x8b": "%8B",
	"\x8c": "%8C",
	"\x8d": "%8D",
	"\x8e": "%8E",
	"\x8f": "%8F",
	"\x90": "%90",
	"\x91": "%91",
	"\x92": "%92",
	"\x93": "%93",
	"\x94": "%94",
	"\x95": "%95",
	"\x96": "%96",
	"\x97": "%97",
	"\x98": "%98",
	"\x99": "%99",
	"\x9a": "%9A",
	"\x9b": "%9B",
	"\x9c": "%9C",
	"\x9d": "%9D",
	"\x9e": "%9E",
	"\x9f": "%9F",
	"\xa0": "%A0",
	"\xa1": "%A1",
	"\xa2": "%A2",
	"\xa3": "%A3",
	"\xa4": "%A4",
	"\xa5": "%A5",
	"\xa6": "%A6",
	"\xa7": "%A7",
	"\xa8": "%A8",
	"\xa9": "%A9",
	"\xaa": "%AA",
	"\xab": "%AB",
	"\xac": "%AC",
	"\xad": "%AD",
	"\xae": "%AE",
	"\xaf": "%AF",
	"\xb0": "%B0",
	"\xb1": "%B1",
	"\xb2": "%B2",
	"\xb3": "%B3",
	"\xb4": "%B4",
	"\xb5": "%B5",
	"\xb6": "%B6",
	"\xb7": "%B7",
	"\xb8": "%B8",
	"\xb9": "%B9",
	"\xba": "%BA",
	"\xbb": "%BB",
	"\xbc": "%BC",
	"\xbd": "%BD",
	"\xbe": "%BE",
	"\xbf": "%BF",
	"\xc0": "%C0",
	"\xc1": "%C1",
	"\xc2": "%C2",
	"\xc3": "%C3",
	"\xc4": "%C4",
	"\xc5": "%C5",
	"\xc6": "%C6",
	"\xc7": "%C7",
	"\xc8": "%C8",
	"\xc9": "%C9",
	"\xca": "%CA",
	"\xcb": "%CB",
	"\xcc": "%CC",
	"\xcd": "%CD",
	"\xce": "%CE",
	"\xcf": "%CF",
	"\xd0": "%D0",
	"\xd1": "%D1",
	"\xd2": "%D2",
	"\xd3": "%D3",
	"\xd4": "%D4",
	"\xd5": "%D5",
	"\xd6": "%D6",
	"\xd7": "%D7",
	"\xd8": "%D8",
	"\xd9": "%D9",
	"\xda": "%DA",
	"\xdb": "%DB",
	"\xdc": "%DC",
	"\xdd": "%DD",
	"\xde": "%DE",
	"\xdf": "%DF",
	"\xe0": "%E0",
	"\xe1": "%E1",
	"\xe2": "%E2",
	"\xe3": "%E3",
	"\xe4": "%E4",
	"\xe5": "%E5",
	"\xe6": "%E6",
	"\xe7": "%E7",
	"\xe8": "%E8",
	"\xe9": "%E9",
	"\xea": "%EA",
	"\xeb": "%EB",
	"\xec": "%EC",
	"\xed": "%ED",
	"\xee": "%EE",
	"\xef": "%EF",
	"\xf0": "%F0",
	"\xf1": "%F1",
	"\xf2": "%F2",
	"\xf3": "%F3",
	"\xf4": "%F4",
	"\xf5": "%F5",
	"\xf6": "%F6",
	"\xf7": "%F7",
	"\xf8": "%F8",
	"\xf9": "%F9",
	"\xfa": "%FA",
	"\xfb": "%FB",
	"\xfc": "%FC",
	"\xfd": "%FD",
	"\xfe": "%FE",
	"\xff": "%FF",
}

func (suite *USSOTestSuite) TestEscape(c *gocheck.C) {
	for in, expected := range escapeTests {
		c.Assert(escape(in), gocheck.Equals, expected)
	}
}
