const utils = require('./utils');
const fs = require('fs');
const SignedXml = require('xml-crypto').SignedXml;

const algorithms = {
  signature: {
    'rsa-sha256': 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    'rsa-sha1': 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
  },
  digest: {
    'sha256': 'http://www.w3.org/2001/04/xmlenc#sha256',
    'sha1': 'http://www.w3.org/2000/09/xmldsig#sha1'
  }
};
const signatureAlgorithm = 'rsa-sha256'
const digestAlgorithm = 'sha256'

exports.signXmlDocument = (doc, callback) => {

  const privateKey = fs.readFileSync('./key.pem', 'utf-8');
  const cert = fs.readFileSync('./cert.pem', 'utf-8');

  function sign() {
    const unsigned = exports.unsigned(doc);
    // const cert = utils.pemToCert(pem);

    const sig = new SignedXml(null, {
      signatureAlgorithm: algorithms.signature[signatureAlgorithm],
      idAttribute: "ID"
    });
    sig.addReference("//*[local-name(.)='Assertion']",
  ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", "http://www.w3.org/2001/10/xml-exc-c14n#"],
  algorithms.digest[digestAlgorithm]);

    sig.signingKey = privateKey;

    const certBase64 = "MIID3zCCAsegAwIBAgIUU7UDKvhUAYXZsdZ2c6BuPkWRuxEwDQYJKoZIhvcNAQELBQAwfzELMAkGA1UEBhMCSU4xDjAMBgNVBAgMBURlbGhpMQ4wDAYDVQQHDAVEZWxoaTEQMA4GA1UECgwHR3Jldml0eTEMMAoGA1UECwwDREVWMQwwCgYDVQQDDANERVYxIjAgBgkqhkiG9w0BCQEWE2d1cmthcmFuQGdyZXZpdHkuaW4wHhcNMjMwODIwMTAwODQyWhcNMjQwODE5MTAwODQyWjB/MQswCQYDVQQGEwJJTjEOMAwGA1UECAwFRGVsaGkxDjAMBgNVBAcMBURlbGhpMRAwDgYDVQQKDAdHcmV2aXR5MQwwCgYDVQQLDANERVYxDDAKBgNVBAMMA0RFVjEiMCAGCSqGSIb3DQEJARYTZ3Vya2FyYW5AZ3Jldml0eS5pbjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANoROaJ+tZ1vP4XDDHYXYTRcMtPfueNzbA9gbPcc+bo13GWwn2V/axV7rRXIm77fByb2i5/DzKvH81oUCcUzbiIGYBN/z12yORjtCS0a/mJCRTTz5HrRkxhCDhkBELtQULd8KbrM66aoWBfckyifqtCsOUSk8mAW/rZjOgL9nGbvuQNdGTFL1oYvPfl5zvALirEkh0IPqPBrEx1zIUJqW8EKGpxD/qgB/+oZfpBeb8BxYimXYIINuFDiloXjv0sAHDvCH2zPi6cVbM+uuJYwLMxYnlHRAfLnbbXNB/1HD3SpBv6Os9tZ/63OHHR3fwRu73Pg82r9828mVJ50d602jWMCAwEAAaNTMFEwHQYDVR0OBBYEFOKUpfLT59OkDD9F4C052jWNQBuNMB8GA1UdIwQYMBaAFOKUpfLT59OkDD9F4C052jWNQBuNMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAJFVPYOvNXbBE3IsVfVmho3WsVBRYHdfnhLWx6I2BixVySwQaSMF4KiSz+taa5sthRAWUEFF2Yp5qxnWY6ijkfzWQBuCPe88/veSD5dOZHjhzNAuDH4bkosqCGMirxrSI3IpVZuIaUwxHVuNcn0f2BF+6aAxaLLoEWJt3t1bL8BACK+LTiHocbHx6IaYcc5Y/JfUalq1ETGOIE5Rvdqr+KuBVTRvFKJ/xgvv+FzovyXNAB8nfVkWKZ7yueVNCorPB3wdTUPAE/Hum2QBHr/iNAwpSrN3ebKKd43Je1uFOXgQsRh3VkXBSFSN3gQYQ3gs/IqldtiJm0L279JJJ4HTnOQ="
    
    sig.keyInfoProvider = {
      getKeyInfo: function (key, prefix) {
        prefix = prefix ? prefix + ':' : '';
        return `<${prefix}X509Data><${prefix}X509Certificate>${certBase64}</${prefix}X509Certificate></${prefix}X509Data>`;
      }
    };

    sig.computeSignature(unsigned, {
      location: { reference: "//*[local-name(.)='Assertion']/*[local-name(.)='Issuer']", action: 'after' },
    });

    return sig.getSignedXml();
  }

  let signed
  try {
    try {
      signed = sign(privateKey)
    } catch (err) {
      signed = sign(utils.fixPemFormatting(privateKey))
    }

    if (callback) {
      setImmediate(callback, null, signed);
    } else {
      return signed;
    }
  } catch (e) {
    if (callback) {
      setImmediate(callback, e)
    }
    throw e
  }
};

exports.unsigned = function (doc, callback) {
  const xml = utils.removeWhitespace(doc.toString());
  if (callback) {
    setImmediate(callback, null, xml)
  } else {
    return xml;
  }
}
