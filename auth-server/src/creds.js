const crypto = require('crypto');
const sql = require('./sqldao');

const gen_salt = () => {
    return crypto.randomBytes(12).toString('ascii');
}

const sha256 = (password, salt) => {
    let hash = crypto.createHash('sha256');
    hash.update(password);
    hash.update(salt);
    let value = hash.digest('hex');
    return {
        salt:salt,
        passwordHash:value
    };
}

const verify = (username, password, db) => {
    if (db.has(username)) {
        const userCreds = db.get(username);
        const creds = sha256(password, userCreds.salt);
        if (creds.passwordHash === userCreds.passwordHash) {
            return true;
        }
    }
    return false;
}


const verify_user = (username, password) => new Promise( (resolve, reject) => {
    sql.getUser(username)
        .then(res => {
            if (res.length < 2)
                return res[0].value;
            else
                reject("Not found");
        })
        .then(b64_hashed_pass => {
            console.log("RETRIEVED STORED HASH");
            const salt = Buffer.from(b64_hashed_pass, "base64").toString("utf8").slice(-12);
            const digest = Buffer.from(b64_hashed_pass, "base64").toString("hex").slice(0,64);
            if (sha256(password,salt).passwordHash === digest)
                resolve(true)
            else
                reject(false);
        })
        .catch(err => reject(err));
});

exports.sha256 = sha256;
exports.verify = verify;
exports.verify_user = verify_user;
exports.gen_salt = gen_salt;
