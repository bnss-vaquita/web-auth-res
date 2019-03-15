require('dotenv').config()
const creds = require('./creds');
const Dao = require('./dao');
const fs   = require('fs');
const jwt = require('jsonwebtoken');
const uuidv4 = require('uuid/v4');

// Init values from env or use defaults
const ISSUER = process.env.ISSUER || 'auth.acme.com';
const EXP = process.env.EXP || '1h';
const KEY_DIR = process.env.KEY_DIR || 'keys';

const priv_key = fs.readFileSync(`${__dirname}/../${KEY_DIR}/auth.acme.com.pem`);
const pub_key = fs.readFileSync(`${__dirname}/../${KEY_DIR}/auth.acme.com.pub.pem`);


// Init the client db with a default
const client_db = new Dao( new Map() );
const _clnt_credentials = creds.sha256('secret', creds.gen_salt());
client_db.set('test_client', _clnt_credentials);

const signOptions = (sub, aud) => (
    {
        issuer: ISSUER,
        subject: sub,
        audience: aud,
        expiresIn: EXP,
        algorithm: 'RS256'
    });

const payload = (data = {}) => (
    {
        ...data,
        jti: uuidv4(),
        token_type: 'bearer',
    });

// Evaluate the password grant
const eval_pass_grant = (request) => {
    const audience = request.audience || 'rs.acme.com',
        client_id = request.client_id,
        client_secret = request.client_secret,
        username = request.username,
        password = request.password,
        subject = request.subject || username;

    return new Promise((resolve, reject) => {
        if (client_id && client_secret && username && password) {
            if (!creds.verify(client_id, client_secret, client_db)) {
                reject('INVALID_CLIENT_CREDS');
            }
            if (audience != 'rs.acme.com') {
                reject('INVALID_AUDIENCE');
            }
            creds.verify_user(username, password)
                .then(_ => {
                    const options = signOptions(subject, audience);
                    resolve(options)
                })
                .catch( _ => {
                    reject('INVALID_USER_CREDS')
                });
        } else {
            reject('INVALID_REQUEST');
        }
    });
}

exports.verify_token = (token) => {
    return jwt.verify(token, pub_key);
}

exports.sign_token = (data, options) => {
    const token = jwt.sign(payload(data), priv_key, options);
    return token;
};

exports.auth = (request) =>
    new Promise( (resolve, reject) => {
        switch (request.grant_type){
            case 'password':
                eval_pass_grant(request)
                    .then((options) =>
                        resolve(options)
                    )
                    .catch((reason) => {
                        reject(reason);
                    });
                break;
            default:
                reject('INVALID_GRANT_TYPE');
        }
    });


