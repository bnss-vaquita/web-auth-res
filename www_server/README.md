# www_server
A simple web server with 2 factor authentication, built as part of the Building Networked Systems Security (EP2520) course @ KTH. 

## Setup
Run `yarn` or `npm` in order to download the project dependencies. 

In order to run the server, you will need a public/private pair of RSA keys and a root certificate. The keys for this project are encrypted using black box. Follow their instructions to add yourself to the keychain, and contact a current admin in order re-incrypt the file so that you can decrypt them. 


If you just want to test with your own local keys, then generate your own keys and certificates using openssl and save it in a folder called `secrets` in the project dir. You want to create all corresponding files that you find under the `keys` folder. 

Then, add `KEY_DIR=secrets` to a `.env` file, so that the app loads your keys and certs. 

Add `www.acme.com` to your hosts file, and point it to `127.0.1.3`. Default HTTPS port for the app is 3433. 

## Running
In order to successfully run the server, you will need to run the authorization and resource server as well. Run it by executing `yarn server` or `npm run server`. 

Make sure to add a client key signed by the root cert to your browser. There should be a corresponding user in the database as well. 






