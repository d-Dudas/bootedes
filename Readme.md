# Thades

## About


This project tends to explore the concept of combining cryptographic algorithms, inspired by 3DES.

## Dependencies

- OpenSSL

### Install dependencies 

Debian/Ubuntu-based distros: `apt install libssl-dev`  
Fedora-based distros: `dnf install openssl-devel`  
Arch-based distros: `pacman -S openssl`  

## Build

```sh
mkdir build && cd build
cmake -GNinja ..
ninja
```

## Usage

```sh
./thades -h
```


