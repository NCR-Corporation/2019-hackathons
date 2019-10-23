// Postman Pre-Request script for signing HTTP requests with NCR Platform HMAC
// by NCR Corporation

var reg = new RegExp('{{([\\w\\-]+)}}', 'g');
function replacePostmanVars(input) {
    if (input) { 
        var match = reg.exec(input);
        while (match) {
            if (pm.variables.get(match[1])) {
                input = input.replace(match[0], pm.variables.get(match[1]));
            }
            match = reg.exec(input);
        }
    }
    return input;
}

//This request requires shared-key and secret-key variables to exist
var shared = pm.variables.get("shared-key");
var secret = pm.variables.get("secret-key");

//Get request verb
var method = pm.request.method;

//Get URL, process variables, and extract URI
var sdk = require('postman-collection');
var url = new sdk.Url(replacePostmanVars(pm.request.url.getRaw()));
var uri = encodeURI(url.getPathWithQuery());

//Get headers object, add non-disabled headers to a header map
var headers = pm.request.headers;
var headerMap = new Map();
for (i = 0; i < headers.count(); i++) {
    var header = headers.idx(i);
    if (!header.disabled) {
        headerMap.set(header.key, header.value);
    }
}

//Get contentType from headers, replace with value from variable if needed
var contentType = replacePostmanVars(headerMap.get("Content-Type"));

//Get md5Hash from headers, replace with value from variable if needed
var md5Hash = replacePostmanVars(headerMap.get("Content-MD5"));

//Get app key from headers, replace with value from variable if needed
var appkey = replacePostmanVars(headerMap.get("nep-application-key"));

//Get correlation ID from headers, replace with value from variable if needed
var correlationId = replacePostmanVars(headerMap.get("nep-correlation-id"));

//Get target org from headers, replace with value from variable if needed
var org = replacePostmanVars(headerMap.get("nep-organization"));

//Get service version on request from headers, replace with value from variable if needed
var serviceVersion = replacePostmanVars(headerMap.get("nep-service-version"));

//Returns an ISO 8601 date time string for HMAC, and sets date header per RFC 7231 
function isoTime() {
    var d = new Date();
    d.setMilliseconds(0);
    headers.upsert({key:"Date", value:d.toUTCString(), disabled:false});
    return d.toISOString();
}

//Time stamp for signing
var time = isoTime();

//Compiles the data to sign
var oneTimeSecret = secret +  time;
var toSign = method + "\n" + uri;
if(contentType) {
    toSign += "\n" + contentType.trim();
}
if(md5Hash) {
    toSign += "\n" + md5Hash.trim();
}
if(appkey) {
    toSign += "\n" + appkey.trim();
}
if(correlationId) {
    toSign += "\n" + correlationId.trim();
}
if(org) {
    toSign += "\n" + org.trim();
}
if(serviceVersion) {
    toSign += "\n" + serviceVersion.trim();
}

//Import crypto-js, create signature and set in header
var cryptojs = require('crypto-js');
var key = cryptojs.HmacSHA512(toSign, oneTimeSecret);
var accessKey = shared + ":" + cryptojs.enc.Base64.stringify(key);
headers.upsert({key:"Authorization", value:"AccessKey " + accessKey, disabled:false});
