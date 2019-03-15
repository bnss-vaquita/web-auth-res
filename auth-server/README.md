# auth-server
A simple OAuth2-compliant authorization server, built as part of the Building Networked Systems Security (EP2520) course @ KTH. 

## Setup
Run `yarn` or `npm` in order to download the project dependencies. 

In order to test, you will need a public/private pair of RSA keys. The keys for this project are encrypted using black box. 
Follow their instructions to add yourself to the keychain, and contact a current admin in order re-incrypt the file so that you can decrypt them. 

If you just want to test with your own local keys, then generate a private key and save it in a folder called `secrets` in the project dir. Using openssl, generate a private key (`auth.acme.com.pem`) as well as its korresponding public key (`auth.acme.com.pub.pem`), generate a CSR and sign it. Save the certificate as `auth.acme.com.crt`. Also add the public CA cert and save it as `ca.crt`. 

Then, add `KEY_DIR=secrets` to a `.env` file, so that the app loads your keys. 
Add auth.acme.com to your hosts file, and point it to 127.0.1.1. 
## Running

Start the server with `yarn server` or `npm run server`. The following request will elicit a correct authentication: 

``` bash
curl -k -i -d '{"username": "test", "password": "password", "client_id": "test_client", "client_secret": "secret", "grant_type":"password"}' -H "Content-Type: application/json" https://auth.acme.com:3443/auth 
```
You can verify this token using the public key. 


