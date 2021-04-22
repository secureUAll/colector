#!/bin/bash

# Generate CA 
openssl req -new -x509 -keyout ca-key -out ca-cert -days 365

#Step 1
keytool -keystore kafka.server.keystore.jks -alias localhost -validity 365 -genkey
#Step 2
openssl req -new -x509 -keyout ca-key -out ca-cert -days 365
keytool -keystore kafka.server.truststore.jks -alias CARoot -import -file ca-cert

#Step 3
keytool -keystore kafka.server.keystore.jks -alias localhost -certreq -file cert-file
openssl x509 -req -CA ca-cert -CAkey ca-key -in cert-file -out cert-signed -days 365 -CAcreateserial -passin pass:CouPHBm7SH4j
keytool -keystore kafka.server.keystore.jks -alias CARoot -import -file ca-cert
keytool -keystore kafka.server.keystore.jks -alias localhost -import -file cert-signed
