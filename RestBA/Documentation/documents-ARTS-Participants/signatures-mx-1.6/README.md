# MX Signature Examples
        
## Requirements

This project requires Java 17 installed.

## Build

Unix:
```shell
./mvnw clean verify
```

Windows:
```shell
mvnw.cmd clean verify
```

## Usage

Sign:
```shell
java -jar signatures-mx.jar --se.highex.example.action=sign --se.highex.example.keystoreFile=/cma/keystore.pfx --se.highex.example.keystorePass=123456 --se.highex.example.keyAlias=te-da551a69-6d1d-4948-b10a-9b1e637de589 --se.highex.example.documentToSign=/cma/example.xml
```

Verify with certificate:

```shell
java -jar signatures-mx.jar --se.highex.example.action=verify --se.highex.example.certFile=/cma/certificate.pem --se.highex.example.documentToVerify=/cma/example-signed.xml
```

Verify with keystore:

```shell
java -jar signatures-mx.jar --se.highex.example.action=verify --se.highex.example.keystoreFile=/cma/keystore.pfx --se.highex.example.keystorePass=123456 --se.highex.example.keyAlias=te-da551a69-6d1d-4948-b10a-9b1e637de589 --se.highex.example.documentToVerify=/cma/example-signed.xml
```
## Parameters

| Parameter                          | Description                                                                                       |
|------------------------------------|---------------------------------------------------------------------------------------------------|
| se.highex.example.action           | Action to perform, `sign` or `verify`.                                                            |
| se.highex.example.keystoreFile     | Path to the keystore file.                                                                        |
| se.highex.example.keystorePass     | Password for the keystore file.                                                                   |
| se.highex.example.keystoreType     | Type of the keystore file. Not required, by default: `JKS`.                                       |
| se.highex.example.keyAlias         | Alias of the key pair in the keystore.                                                            |
| se.highex.example.keyPass          | Password for the private key. Not required, by default `keystorePass` will be used.               |
| se.highex.example.certFile         | Path to the certificate file (DER or PEM). Used for `verify` with certificate (without keystore). |
| se.highex.example.documentToSign   | Path to document to sign. Required for `sign`.                                                    |
| se.highex.example.documentToVerify | Path to document to verify. Required for `verify`.                                                |
