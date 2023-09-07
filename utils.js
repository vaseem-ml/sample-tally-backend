const fs = require('fs');
const Parser = require('@xmldom/xmldom').DOMParser;

exports.pemToCert = function(pem) {
  const cert = /-----BEGIN CERTIFICATE-----([^-]*)-----END CERTIFICATE-----/g.exec(pem.toString());
  if (cert && cert.length > 0) {
    return cert[1].replace(/[\n|\r\n]/g, '');
  }

  return null;
};

exports.reportError = function(err, callback){
  if (callback){
    setImmediate(function(){
      callback(err);
    });
  }
};

exports.uid = function(len) {
  const buf = []
      , chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
      , charlen = chars.length;

  for (let i = 0; i < len; ++i) {
    buf.push(chars[getRandomInt(0, charlen - 1)]);
  }

  return buf.join('');
};

exports.removeWhitespace = function(xml) {
  return xml
      .replace(/\r\n/g, '')
      .replace(/\n/g, '')
      .replace(/>(\s*)</g, '><') //unindent
      .trim();
};

function getRandomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

exports.factoryForNode = function factoryForNode(pathToTemplate) {
  const template = fs.readFileSync(pathToTemplate);
  const prototypeDoc = new Parser().parseFromString(template.toString());

  return function () {
    return prototypeDoc.cloneNode(true);
  };
};

exports.fixPemFormatting = function (pem) {
  let pemEntries = pem.toString().matchAll(/([-]{5}[^-\r\n]+[-]{5})([^-]*)([-]{5}[^-\r\n]+[-]{5})/g);
  let fixedPem = ''
  for (const pemParts of pemEntries) {
    fixedPem = fixedPem.concat(`${pemParts[1]}\n${pemParts[2].replaceAll(/[\r\n]/g, '')}\n${pemParts[3]}\n`)
  }
  if (fixedPem.length === 0) {
    return pem;
  }

  return Buffer.from(fixedPem)
}
