# acme-client
[![Build](https://github.com/stgloorious/acme-client/actions/workflows/build.yml/badge.svg)](https://github.com/stgloorious/acme-client/actions/workflows/build.yml)
[![Test](https://github.com/stgloorious/acme-client/actions/workflows/test.yml/badge.svg)](https://github.com/stgloorious/acme-client/actions/workflows/test.yml)
[![codecov](https://codecov.io/gh/stgloorious/acme-client/branch/master/graph/badge.svg?token=H96Q1DZIG0)](https://codecov.io/gh/stgloorious/acme-client)

Simple ACME client written in C 

## What is ACME?
ACME (Automatic Certificate Management Environment) is a protocol specified by [RFC 8555](https://www.rfc-editor.org/rfc/rfc8555) that is widely used for obtaining Let's Encrypt and other certificates automatically. A user (ACME client machine, usually automated) can request a certificate for a domain it has control over by sending a request to an ACME server. The ACME server will then generate challenges for the client which have to be fulfilled in order to prove control over the requested domains. A challenge is a random token that the client needs to serve via HTTP or DNS TXT record. If the conditions are met and the challenges are fulfilled before timeout, the server will issue the certificate and make it available for the client.

## Features
- Single or multidomain certificate requests to an ACME-enabled CA, such as Let's Encrypt
- HTTP-01 validation
- Automatic HTTP challenge validation, no user interaction required

## Usage 
    Usage: acme-client [OPTION...]
    Simple ACME client written in C

      -a, --account-key=KEYFILE  Account private key
      -c, --cert=CERTFILE        CA certificate file used by the ACME server
      -d, --domain=DOMAIN        Domain for which to request the certificate. Can
                                 be used multiple times.
      -p, --port=PORT            Port number the HTTP server should bind to
      -u, --dir=DIR_URL          Directory URL of the ACME server that should be
                                 used.
      -v, --verbose              Produce verbose output
      -y, --agree-tos            Always agree to the terms of service
      -?, --help                 Give this help list
          --usage                Give a short usage message
      -V, --version              Print program version


### Examples
#### Obtaining a Let's Encrypt certificate
1. Stop your webserver, so acme-client can bind to Port 80. For instance if you're using nginx and systemd:

        systemctl stop nginx
2. Run acme-client

        ./acme-client --domain <YOUR-DOMAIN-NAME>
3. Copy client.key and cert.crt to the right location & restart webserver 

        systemctl start nginx

## Installation
A binary release is planned as soon as acme-client is more stable. For now, you have to compile it yourself. Linux only.

acme-client comes in two configurations: Debug and Release. The debug build contains all the tests that are also used in the Github testing CI pipeline. It has some unit tests and does testing against a local [ACME testing server](https://github.com/letsencrypt/pebble). It uses Valgrind to spot memory leaks and other memory-related issues.

### Building from source
#### Dependencies
Besides a standard GCC installation you need the following packages.
For the release build:
- OpenSSL >= 3.0.0
- cURL
- [cJSON](https://github.com/DaveGamble/cJSON)
- CMake >= 3.20

#### Ubuntu 22.04 (Release build)
    sudo apt-get install libcurl4-openssl-dev libcjson-dev openssl libssl-dev cmake

Needed additionally for testing (debug build):
- [Pebble](https://github.com/letsencrypt/pebble)
- Python >= 3.9
- Valgrind
    
#### Ubuntu 22.04 (Debug build)
    sudo apt-get install libcurl4-openssl-dev libcjson-dev openssl libssl-dev cmake valgrind pebble
        
#### Using CMake
Get the sources: 

    git clone https://github.com/stgloorious/acme-client && cd acme-client
    
Compile (Release build):

    cmake -DCMAKE_BUILD_TYPE=Release -B build
    cd build && make
     
Compile and test (Debug build):

    cmake -DCMAKE_BUILD_TYPE=Debug -B build
    cd build && make all test
        
        

