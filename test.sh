#!/bin/bash
msg="${@:-hello world}"
node index.js "$msg" | base64 -d | openssl pkeyutl -decrypt -inkey privatekey.pem -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256  -pkeyopt rsa_mgf1_md:sha256
