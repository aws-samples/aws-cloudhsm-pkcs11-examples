# aws-cloudhsm-pkcs11-examples


[![Build Status](https://travis-ci.org/aws-samples/aws-cloudhsm-pkcs11-examples.svg?branch=master)](https://travis-ci.org/aws-samples/aws-cloudhsm-pkcs11-examples)

## Building the examples

### Depedencies

The examples are tested on an Amazon Linux 2 AMI. You will need to have the
following packages installed:

* GCC/C++ 7.3.1-5
* OpenSSL 1.0.2k
* CMake 2.8.12

You can install these packages on Amazon Linux 2 by running

```
sudo yum install -y cmake gcc gcc-c++ openssl-devel
```

### Building

Create a build directory and execute CMake. This will create a Makefile for the
project. Run make to build the examples.

```
mkdir build/
cd build/
cmake .. -DHSM_USER=<user> -DHSM_PASSWORD=<password> -DTRUSTED_WRAPPING_KEY_HANDLE=<trusted_key>
make
```

### Running

Application binaries are in the `build/src/` directory. Applications will request
a PIN on the command line. The CloudHSM PKCS#11 library will be used by default.

```
# After running make
$ src/digest/digest

	--pin <user:password>
	[--library <path/to/pkcs11>]
```

### Testing all samples:

To run and test all samples, run the command ```make test```

