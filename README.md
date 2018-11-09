# aws-cloudhsm-pkcs11-examples

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
cmake ..
make
```

This will create application binaries in the `c/` directory.
