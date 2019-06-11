<p align="center">
  <h2 align="center">gdzip</h2>
  <p align="center">
    <a href="https://goreportcard.com/report/github.com/w33zl3p00tch/gdzip"><img src="https://goreportcard.com/badge/github.com/w33zl3p00tch/gdzip"></a>
  </p>
</p>

## Synopsis

gdzip is a command line tool to compress and encrypt a file or folder.


Internally, the given files and/or folders are compressed and stored as tar.gz archives that retain the original file metadata. The data are split into chunks while encrypting, and encryption is done done using AES256-GCM and/or ChaCha20-Poly1305. All this happens in RAM, so no temporary files will be used.

Keys are generated using the scrypt key derivation function.

The encrypted files provide no information about their contents or their contents' filenames.

Encrypted files may be safely renamed and even the extension may be altered or left out.


Please report any bugs you might find. Suggestions and feature requests are welcome.



## Usage

To print a short help:
```
$ gdzip -h
```

to encrypt a file or folder:

```
$ gdzip -encrypt FILE_TO_ENCRYPT
```

to decrypt a file:

```
$ gdzip -decrypt FILE.gdz
```

In both cases the user will be asked to provide a password.


Example with more options set:
```
$ gdzip -encrypt PATH_TO_FILE -mode 3 -dest /tmp/
```

encrypts a file using mode 3 (AES with ChaCha20) to /tmp/FILENAME.gdz


## Installation

Binaries for Windows, Linux, Mac OS X and FreeBSD are available at:
https://github.com/w33zl3p00tch/gdzip/releases

Simply extract the binary to a folder in your PATH, e.g. /usr/local and make sure that it is executable.



## Installation from source

gdzip is written in go. The simplest way is to 'go get' it:

```
$ go get github.com/w33zl3p00tch/gdzip
```

Alternatively, you can clone the source and install the dependencies (apart from the base library these are golang.org/x/crypto/scrypt and golang.org/x/crypto/chacha20poly1305).



## Revision history

```
v1.0.1: added a build script for cross compiling and upload new binaries, fixed Windows build
v1.0.0: nothing new, really. I've considered gdzip stable enough for a first release.
v0.0.2: alpha2 release
v0.0.1: initial commit; alpha release for testing
```

## Roadmap

```
My rough plan for future versions
v1.1.0: reorganize the package structure to make GUI development easier
v1.2.0: add GUI
v2.0.0: add support for asymmetric encryption (RSA/PGP) - this is rather tricky to do right and I want to support standard PKI implementations, so this might take a while
```

## License

gdzip is released under a BSD-Style license.

