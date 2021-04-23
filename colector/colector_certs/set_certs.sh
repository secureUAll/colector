#!/bin/bash


#Step 1
keytool -keystore kafka.client.keystore.jks -alias localhost -validity 365 -genkey -keyalg RSA
#Step 2
keytool -keystore kafka.client.truststore.jks -alias CARoot -import -file  ../../kafka_certs/ca-cert 
keytool -keystore kafka.client.keystore.jks -alias CARoot -import -file  ../../kafka_certs/ca-cert 

#Step 3
keytool -keystore kafka.client.keystore.jks -alias localhost -certreq -file cert-file
openssl x509 -req -CA ../../kafka_certs/ca-cert -CAkey ../../kafka_certs/ca-key -in cert-file -out cert-signed -days 365 -CAcreateserial -passin pass:CouPHBm7SH4j
keytool -keystore kafka.client.keystore.jks -alias CARoot -import -file ca-cert
keytool -keystore kafka.client.keystore.jks -alias localhost -import -file cert-signed

keytool -exportcert -alias localhost -keystore kafka.client.keystore.jks -rfc -file certificate.pem
keytool -v -importkeystore -srckeystore kafka.client.keystore.jks -srcalias localhost -destkeystore cert_and_key.p12 -deststoretype PKCS12
openssl pkcs12 -in cert_and_key.p12 -nocerts -nodes
keytool -exportcert -alias CARoot -keystore kafka.client.keystore.jks -rfc -file CARoot.pem
