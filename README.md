# acme-client
[![CMake](https://github.com/stgloorious/acme-client/actions/workflows/cmake.yml/badge.svg?branch=master)](https://github.com/stgloorious/acme-client/actions/workflows/cmake.yml)

Simple ACME client written in C

## What is ACME?
ACME (Automatic Certificate Management Environment) is a protocol specified by [RFC 8555](https://www.rfc-editor.org/rfc/rfc8555) that is widely used for obtaining Let's Encrypt and other certificates automatically. A user (ACME client machine, usually automated) can request a certificate for a domain it has control over by sending a request to an ACME server. The ACME server will then generate challenges for the client which have to be fulfilled in order to prove control over the requested domains. A challenge is a random token that the client needs to serve via HTTP or DNS TXT record. If the conditions are met and the challenges are fulfilled before timeout, the server will issue the certificate and make it available for the client.

## Features
- Single and multidomain certificate issuance
- http01 validation
- Automatic HTTP challenge validation

### TODO's
- dns01 validation
- Support for wildcard domains
- Testing

## Usage 
    Usage: acme-client [OPTION...] CHALLENGE TYPE {dns01 | http01}
    Simple ACME client written in C

          --cert[=CERTFILE]      CA certificate file used by the ACME server
      -d, --domain=DOMAIN        Domain for which to request the certificate. Can
                                 be used multiple times.
      -p, --port=PORT            Port number the HTTP server should bind to
      -r, --record=IPv4_ADDRESS  IPv4 the HTTP server should bind to
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

        ./acme-client --domain <YOUR-DOMAIN-NAME> --record <YOUR-IPv4-ADDRESS> http01
3. Copy client.key and cert.crt to the right location & restart webserver 

        systemctl start nginx
    
#### Obtain a certificate from local [Pebble testing server](https://github.com/letsencrypt/pebble)

    ./acme-client http01 --agree-tos --dir https://pebble:14000/dir --domain example.com --cert=../pebble.minica.pem --port 5080

    Terms of service are located at data:text/plain,Do%20what%20thou%20wilt
    Accepting terms of service.
    Performing automatic validation
    HTTP challenge server started on port 5080
    Terminated HTTP challenge server
    All domains were successfully verified.
    Certificate saved to cert.crt


## Installation
### Building from source
#### Dependencies
- OpenSSL >= 3.0.0
- cURL
- [cJSON](https://github.com/DaveGamble/cJSON)
- cmake

#### Ubuntu 22.04
    sudo apt install libcurl4-openssl-dev libcjson-dev openssl libssl-dev cmake
#### Gentoo
    sudo emerge --quiet --ask dev-libs/cJSON =dev-libs/openssl-3.0.7 dev-util/cmake
        
#### Using CMake
1. Getting the sources

        git clone https://github.com/stgloorious/acme-client
        cd acme-client
    
2. Compile

        mkdir build
        cd build
        cmake ..
        make
