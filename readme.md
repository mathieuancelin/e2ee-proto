# E2EE messages

A prototype of E2EE messaging app to explore E2EE techniques. 
Uses in browser crypto to encrypt and decrypt messages client side using users RSA private key.
Private key is generated client side and saved server side encrypted with user password using AES 256.
Everything server side is encrypted 

## Run in prod

```sh
yarn install
yarn build-frontend
yarn start 
# or node server.js
open http://127.0.0.1:8080/
```

## Run in dev

```
yarn install
yarn start-frontend
yarn start-server
open http://127.0.0.1:8080/
```