const https = require('https');
const fs = require('fs');
const express = require('express');
const bodyParser = require('body-parser');
const auth = require('./auth');
const jwt = require('jsonwebtoken');
const tfaManager = require('./tfamanager').manager;

const app = express();
const ip = process.env.IP || '127.0.1.1';
const http_port = process.env.HTTP_PORT || 3000;
const https_port = process.env.HTTPS_PORT || 3443;

const KEY_DIR = process.env.KEY_DIR || 'keys';
const CRT = process.env.CRT_NAME || 'auth.acme.com.crt';
const CA_CRT = process.env.CA_CRT_NAME || 'ca.crt';
const HOSTNAME = process.env.HOSTNAME || 'auth.acme.com';

const options = {
    key: fs.readFileSync(`${__dirname}/../${KEY_DIR}/auth.acme.com.pem`),
    cert: fs.readFileSync(`${__dirname}/../${KEY_DIR}/${CRT}`),
    requestCert: true,
    rejectUnauthorized: false,
    ca: [ fs.readFileSync(`${__dirname}/../${KEY_DIR}/${CA_CRT}`) ]
};

// HTTPS Only
// Will only work if we listen on HTTP
const requireHTTPS = (req, res, next) => {
  if (!req.secure) {
      console.log(`redirect to https://${HOSTNAME}:${https_port}${req.url}`);
      return res.redirect(`https://${HOSTNAME}:${https_port}${req.url}`);
  }
  next();
}

app.use(requireHTTPS);
app.use(bodyParser.json());

app.get('/', (req, res) => {
	const cert = req.connection.getPeerCertificate();
    if(req.client.authorized) {
        res.send(`Hello ${cert.subject.CN}, your certificate was issued by ${cert.issuer.CN}!`)
    }
    else {
        res.send('Access Denied!');
    }
});

app.post('/auth', (req, res) => {
    auth.auth(req.body)
        .then((options) => {
            const payload = req.body.payload;
            return auth.sign_token({payload},options);
        })
        .then((token) => {
            const response = {access_token: token};
            res.setHeader('Content-Type', 'application/json');
            res.send(response)
        })
        .catch((reason) => {
            switch (reason) {
                case 'INVAlID_USER_CREDS':
                    res.status(401)
                        .send('Username or Password invalid\n');
                    break;
                default:
                    res.status(400)
                        .send(`${reason}\n`)
            }
        });

});
app.listen(http_port, ip, () => console.log(`HTTP on ${ip}:${http_port}`));
https.createServer(options, app).listen(https_port, ip, () => console.log(`HTTPS on ${ip}:${https_port}`));
