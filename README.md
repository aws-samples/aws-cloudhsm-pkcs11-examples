# aws-cloudhsm-pkcs11-examples


[![Build Status](https://travis-ci.org/aws-samples/aws-cloudhsm-pkcs11-examples.svg?branch=master)](https://travis-ci.org/aws-samples/aws-cloudhsm-pkcs11-examples)

## Building the examples

### Depedencies

#### Linux

The examples are tested on an Amazon Linux 2 AMI. You will need to have the
following packages installed:

* GCC/C++ 7.3.1-5
* OpenSSL 1.0.2k
* CMake 2.8.12

You can install these packages on Amazon Linux 2 by running

```
sudo yum install -y cmake gcc gcc-c++ openssl-devel
```

#### Windows

The examples are tested on Windows Server 2019 AMI. You will need to have the
following installed:

* (Microsoft C++ Build Tools)[https://visualstudio.microsoft.com/visual-cpp-build-tools/]
* CMake 3.20


### Building

#### Linux

Create a build directory and execute CMake. This will create a Makefile for the
project. Run make to build the examples. Specifying HSM_USER, HSM_PASSWORD, and
TRUSTED_WRAPPING_KEY_HANDLE are optional for source build, but required for tests.

```
mkdir build/
cd build/
cmake .. -DHSM_USER=<user> -DHSM_PASSWORD=<password> -DTRUSTED_WRAPPING_KEY_HANDLE=<trusted_key>
make
```

#### Windows

Create a build directory and execute CMake. This will create a Makefile for the
project. Run make to build the examples. Specifying HSM_USER, HSM_PASSWORD, and
TRUSTED_WRAPPING_KEY_HANDLE are optional for source build, but required for tests.

```
mkdir build/
cd build/
cmake .. -DHSM_USER=<user> -DHSM_PASSWORD=<password> -DTRUSTED_WRAPPING_KEY_HANDLE=<trusted_key>
```

Now you will be able to open and use `ALL_BUILD.vcxproj` to build, run, or edit
the samples.

### Running

Application binaries are in the `build/src/` directory. Applications will request
a PIN on the command line. The CloudHSM PKCS#11 library will be used by default.
In Linux, the binaries have no file type. In Windows, the binaries will end in `.exe`

#### Linux

```
# After running make
$ src/digest/digest

	--pin <user:password>
	[--library <path/to/pkcs11>]
```

#### Windows

```
# After building
> src/digest/digest.exe

	--pin <user:password>
	[--library <path/to/pkcs11>]
```

### Testing all samples:

#### Linux

To run and test all samples, run the command ```make test```

#### Windows

Open and build `RUN_TESTS.vcxproj`. The build will run and verify the binaries.
Note that not all samples are currently support on Windows through SDK 5.
Please see https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-apis.html
for the latest list of support PKCS#11 functions in SDK 5.

