#!/bin/bash
msg="${@:-hello world}"
node index.js "$msg" | base64 -d | openssl rsautl -decrypt -inkey privatekey.pem 
