const express = require("express")
const dotenv = require("dotenv")
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const { Builder, parseStringPromise } = require('xml2js');
const fs = require('fs');
const uuidv4 = require('uuid').v4;
const zlib = require('zlib');
const { signXmlDocument } = require('./sign');
const cors = require("cors")
dotenv.config()

const app = express()
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cors({
    origin: '*', // specify the allowed origin
    credentials: true, // allow credentials (cookies) to be sent with the request
  }));
app.use(cookieParser());

const users = [
    {
        name: 'Gurkaran Singh',
        avatar: 'https://gw.alipayobjects.com/zos/antfincdn/XAosXuNZyF/BiazfanxmamNRoxxVxka.png',
        userid: 1,
        email: 'gurkaran@grevity.in',
        username: "gurkaran",
        password: "123456",
        currentAuthority: "admin",
        associated_with: [{id: 1, name: "Demo Company"}, { id: 2, name: "Grevity" }],
        tally_accounts: [
            {
                company: 1,
                username: "NDOISUFBonboisd",
                password: "NDOISUFBonboisd"
            },
            {
                company: 2,
                username: "UsfY776Sr",
                password: "UsfY776Sr"
            }
        ]
    }
]

/// Sample Frontend Endpoints...
app.get("/currentUser", (req, res) => {

    if(req.cookies.token) {
        const _token = req.cookies.token
        const secretKey = 'your_secret_key';
        let user = jwt.decode(req.cookies.token)
        res.send({
            success: true,
            data: users.find((e) => e.userid == user.id)
        })
    }
    
})

app.post("/login", (req, res) => {
    const _user = users.find((e) => e.username == req.body.username)
    if (_user && _user.password == req.body.password) {
        const secretKey = 'your_secret_key';
        const token = jwt.sign({ id: _user.userid }, secretKey, { expiresIn: '365d' });

        res.cookie('token', token, { httpOnly: true });
        res.send({
            status: 'ok',
            type: 'account',
            currentAuthority: _user.currentAuthority,
        })
    } else {
        res.send({
            status: 401,
            message: "Unauthorised"
        })
    }
})


/// SSO Endpoint...
function generateSAMLResponse(username, inResponseTo) {
    const responseId = 'response_' + uuidv4();
    const assertionId = 'assertion_' + uuidv4();

    const samlResponse = {
        'samlp:Response': {
            '$': {
                'xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
                'ID': responseId,
                'Version': '2.0',
                'IssueInstant': new Date().toISOString(),
                'InResponseTo': inResponseTo
            },
            'saml:Issuer': {
                '$': {
                    'xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion'
                },
                '_': 'http://20.204.153.20:4000/saml/metadata'
            },
            'samlp:Status': {
                'samlp:StatusCode': {
                    '$': {
                        'Value': 'urn:oasis:names:tc:SAML:2.0:status:Success'
                    }
                }
            },
            'saml:Assertion': {
                '$': {
                    'xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
                    'Version': '2.0',
                    'ID': assertionId,
                    'IssueInstant': new Date().toISOString()
                },
                'saml:Issuer': 'http://20.204.153.20:4000/saml/metadata',
                'saml:Subject': {
                    'saml:NameID': {
                        '$': {
                            'Format': 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'
                        },
                        '_': username
                    },
                    'saml:SubjectConfirmation': {
                        '$': {
                            'Method': 'urn:oasis:names:tc:SAML:2.0:cm:bearer'
                        },
                        'saml:SubjectConfirmationData': {
                            '$': {
                                'NotOnOrAfter': new Date(Date.now() + 5 * 60 * 1000).toISOString(), // 5 minutes from now
                                'Recipient': 'https://toc.grevity.in/guacamole/api/ext/saml/callback',
                                'InResponseTo': inResponseTo
                            }
                        }
                    }
                },
                'saml:Conditions': {
                    '$': {
                        'NotBefore': new Date().toISOString(),
                        'NotOnOrAfter': new Date(Date.now() + 5 * 60 * 1000).toISOString() // 5 minutes from now
                    },
                    'saml:AudienceRestriction': {
                        'saml:Audience': 'https://toc.grevity.in/guacamole'
                    }
                },
                'saml:AuthnStatement': {
                    '$': {
                        'AuthnInstant': new Date().toISOString(),
                        'SessionNotOnOrAfter': new Date(Date.now() + 2 * 60 * 60 * 1000).toISOString(), // 2 hours from now
                        'SessionIndex': '_session_' + uuidv4()
                    },
                    'saml:AuthnContext': {
                        'saml:AuthnContextClassRef': 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'
                    }
                }
            }
        }
    };

    const builder = new Builder();
    let xml = builder.buildObject(samlResponse);

    // return await addSign(xml, fs.readFileSync('./key.pem', 'utf8'), fs.readFileSync('./cert.pem', 'utf8'));
    // return signSAMLResponse(xml, assertionId); // Ensure you're signing the Assertion and referencing its ID correctly in the signature

    return signXmlDocument(xml)
}

app.get('/saml/metadata', (req, res) => {
    const xml = fs.readFileSync('./meta.xml', 'utf8');
    res.type('application/xml');
    res.send(xml);
});

app.post('/sso', async (req, res) => {

    console.log('request body', req.body)
    const samlRequest = req.body.SAMLRequest;
    const username = req.body.username

    // Decode, then Inflate (assuming it's URL-encoded and deflated)
    const decoded = Buffer.from(samlRequest, 'base64');
    const inflated = zlib.inflateRawSync(decoded).toString();

    // Parse the XML
    const parsed = await parseStringPromise(inflated);
    // Validate (simplified for this example)
    const issuer = parsed['samlp:AuthnRequest']['saml:Issuer'][0];
    if (issuer !== 'https://toc.grevity.in/guacamole') {
        res.status(400).send('Invalid Issuer');
        return;
    }
    // Extract Information
    const acsUrl = parsed['samlp:AuthnRequest'].$.AssertionConsumerServiceURL;
    const requestId = parsed['samlp:AuthnRequest'].$.ID;

    // Generate SAMLResponse (using a function like generateSAMLResponse)
    // Ant Portal -> Gurkaran -> Mohit's Company -> NDOISUFBonboisd
    const samlResponse = generateSAMLResponse(username, requestId);

    // const samlResponse = generateSAMLResponse('test', requestId);
    // const signedSAMLResponse = signSAMLResponse(samlResponse);
    const base64SAMLResponse = Buffer.from(samlResponse).toString('base64');
    console.log('base samel response', base64SAMLResponse)
    res.send(base64SAMLResponse);

});


const PORT = process.env.PORT
app.listen(PORT || 3000, () => console.log(`Server started on port: ${PORT}\nNetwork: http://${process.env.PUBLIC_IP}:${process.env.PORT}`))
