const https = require('https');
const fs = require('fs');
const express = require('express');
const bodyParser = require('body-parser');
const login = require('./login');
const notp = require('notp');

const app = express();
const ip = process.env.IP || '127.0.1.3';
const http_port = process.env.HTTP_PORT || 3000;
const https_port = process.env.HTTPS_PORT || 3443;

const KEY_DIR = process.env.KEY_DIR || 'keys';
const CRT = process.env.CRT_NAME || 'www.acme.com.crt';
const CA_CRT = process.env.CA_CRT_NAME || 'ca.crt';
const HOSTNAME = process.env.HOSTNAME || 'www.acme.com';

const options = {
    key: fs.readFileSync(`${__dirname}/../${KEY_DIR}/www.acme.com.pem`),
    cert: fs.readFileSync(`${__dirname}/../${KEY_DIR}/${CRT}`),
    requestCert: true,
    rejectUnauthorized: false,
    ca: [ fs.readFileSync(`${__dirname}/../${KEY_DIR}/${CA_CRT}`) ]
};

const auth_options = {
    ...options,
    port: 443,
    hostname: 'auth.acme.com',
    path: '/auth',
    method: 'POST'
}

const rs_options = {
    ...options,
    port: 443,
    hostname: 'rs.acme.com',
    method: 'GET'
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
app.use(bodyParser.urlencoded());

const token_req = (username, password, success, error) => {
    const payload = JSON.stringify({
        grant_type: "password",
        username: username,
        password: password,
        client_id: "test_client",
        client_secret: "secret"
    });
    const req_options = { ...auth_options,
        headers: {
            'Content-Type': 'application/json',
            'Content-Length': payload.length
        }
    };

    // Request a token
    const request = https.request(req_options, (auth_res) => {
        if (auth_res.statusCode != 200) {
            error(auth_res.statusCode);
        } else {
            auth_res.on('data', (data) => {
                const response = JSON.parse(data);
                success(response);
            });
        }
    });
    request.write(payload);
    request.end();
    request.on('error', (e) => {
        console.error(e);
    });
}

const file_req = (username, token, success, error) => {
    const req_options = {
        ...rs_options,
        path: `/${username}/files`,
        headers: {
            'Authorization': `Bearer ${token}`
        }
    };
    // Retrive the list of files
    const request = https.request(req_options, (rs_res) => {
        if (rs_res.statusCode != 200) {
            error(rs_res.statusCode);
        } else {
            rs_res.on('data', (data) => {
                success(JSON.parse(data));
            });
        }
    });
    request.end();
    request.on('error', (e) => {
        console.error(e);
    });
}

const secret_req = (username, token, success, error) => {
    const req_options = {
        ...rs_options,
        path: `/${username}/key`,
        headers: {
            'Authorization': `Bearer ${token}`
        }
    };
    // Retrive the key
    const request = https.request(req_options, (rs_res) => {
        if (rs_res.statusCode != 200) {
            error(rs_res.statusCode);
        } else {
            rs_res.on('data', (data) => {
                success(JSON.parse(data));
            });
        }
    });
    request.end();
    request.on('error', (e) => {
        console.error(e);
    });

}

const totp = (key) => {
};

app.post('/', (req, res) => {
	const cert = req.connection.getPeerCertificate();
    const username = req.body.username;
    const password = req.body.password;
    // Authenticated certificate flow
    if(req.client.authorized && username === cert.subject.CN) {
        // Request the token
        token_req(
            username,
            password,
            (t_response) => {
                const token = t_response.access_token;
                // Request the file
                file_req(
                    username,
                    token,
                    (f_response) => {
                        res.send(`
                                     <html>
                                         <body>
                                             <center>
                                             <h1>ACME CORPORATION</h1>
                                             <h2>Super Secret Page</h2>
                                             <p>Here are your files: ${f_response} </p>
                                         </center>
                                     </body>
                                 </html>
                                         `);
                    },
                    (error_code) => {
                        res.status(error_code)
                            .send("Login Failed!\n");
                    }
                )
            },
            (error) => {
            res.status(auth_res.statusCode)
                .send("Login failed");
            }
        );

    }
    else {
        const totp = req.body.totp;
        token_req(
            username,
            password,
            (t_response) => {
                const token = t_response.access_token;
                secret_req(
                    username,
                    token,
                    (s_response) => {
                        const key = Buffer.from(s_response.key,'base64').toString('utf8');
                        const login = notp.totp.verify(totp, key);

                        if(login) {
                            // Request the file
                            file_req(
                                username,
                                token,
                                (f_response) => {
                                    res.send(`
                                     <html>
                                         <body>
                                             <center>
                                             <h1>ACME CORPORATION</h1>
                                             <h2>Super Secret Page</h2>
                                             <p>Here are your files: ${f_response} </p>
                                         </center>
                                     </body>
                                 </html>
                                         `);
                                },
                                (error_code) => {
                                    res.status(error_code)
                                        .send("Login Failed!\n");
                                }
                            )

                        } else {
                            res.status(400)
                                .send("Login Failed!\n");
                        };

                    },
                    (error_code) => {
                        res.status(error_code)
                            .send("Login Failed!\n");
                    }
                );
            },
            (error_code) => {
                res.status(error_code)
                    .send("Login Failed!");
            }
        );
    }

});

app.get('/', (req, res) => {
	const cert = req.connection.getPeerCertificate();
    if(req.client.authorized) {
        res.send(login.login(cert.subject.CN));
    }
    else {
        res.send(login.totp());
    }
});

app.listen(http_port, ip, () => console.log(`HTTP on ${ip}:${http_port}`));
https.createServer(options, app).listen(https_port, ip, () => console.log(`HTTPS on ${ip}:${https_port}`));

