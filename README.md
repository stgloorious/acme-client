# acme-client
[![CMake](https://github.com/stgloorious/acme-client/actions/workflows/cmake.yml/badge.svg?branch=master)](https://github.com/stgloorious/acme-client/actions/workflows/cmake.yml)

Simple ACME client written in C

## Installation
### Building from source
#### Dependencies
- OpenSSL 3
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
