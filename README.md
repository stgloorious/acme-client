# acme-client
[![CMake](https://github.com/stgloorious/acme-client/actions/workflows/cmake.yml/badge.svg?branch=master)](https://github.com/stgloorious/acme-client/actions/workflows/cmake.yml)

Simple ACME client written in C

## What is ACME?
ACME (Automatic Certificate Management Environment) is a protocol specified by [RFC 8555](https://www.rfc-editor.org/rfc/rfc8555) that is widely used for obtaining Let's Encrypt and other certificates automatically. A user (ACME client machine, usually automated) can request a certificate for a domain it has control over by sending a request to an ACME server. The ACME server will then generate challenges for the client which have to be fulfilled in order to prove control over the requested domains. A challenge is a random token that the client needs to serve via HTTP or DNS TXT record. If the conditions are met and the challenges are fulfilled before timeout, the server will issue the certificate and make it available for the client.

## Usage 
TODO

## Installation
### Building from source
#### Dependencies
- OpenSSL >= 3.0.0
- cURL
- [cJSON](https://github.com/DaveGamble/cJSON)

#### Ubuntu 22.04
    sudo apt install libcurl4-openssl-dev libcjson-dev openssl
#### Gentoo
    sudo emerge --quiet --ask dev-libs/cJSON =dev-libs/openssl-3.0.7
        
#### Using CMake
1. Getting the sources

        git clone https://github.com/stgloorious/acme-client
        cd acme-client
    
2. Compilation

        mkdir build
        cd build
        cmake ..
        make
