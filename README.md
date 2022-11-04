# acme-client
Simple ACME client written in C

## Installation
### Building from source
#### Dependencies
- OpenSSL 3
- cURL
- [cJSON](https://github.com/DaveGamble/cJSON)
#### Using CMake
1. Getting the sources

        git clone https://github.com/stgloorious/acme-client
        cd acme-client
    
2. Compilation

        mkdir build
        cd build
        cmake ..
        make
