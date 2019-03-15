const mariadb = require('mariadb');
const fs = require('fs');

const KEY_DIR = process.env.KEY_DIR || 'keys';
const CA_CRT = process.env.CA_CRT_NAME || 'ca.crt';
const PASS = process.env.AUTH_SERVER_USR_PASSWORD;

const getUser = (username) => new Promise((resolve, reject) => {
    mariadb.createConnection({
        host: 'mysql.acme.com',
        user:'auth_server',
        password: PASS,
        database: 'radius',
        ssl: {
            ca: fs.readFileSync(`${__dirname}/../${KEY_DIR}/${CA_CRT}`)
        }
    }).then( conn => {
            return conn.query("SELECT value FROM radcheck WHERE username=(?)",username)
                .then( row => {
                    conn.end();
                    if (row.length > 0)
                        resolve(row);
                    else
                        reject(`User ${username} not found`);
                })
                .catch( err => {
                    reject(err);
                });
        })
        .catch( err => {
            reject(err);
        });
});

getUser("test2@acme.com")
    .then( res => console.log(res))
    .catch( err => console.log(err));

exports.getUser = getUser;


