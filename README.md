# Accelerating Encrypted Deduplication via SGX

## Introduction

Encrypted deduplication preserves the deduplication effectiveness on encrypted data and is attractive for outsourced storage.  However, existing encrypted deduplication approaches build on expensive cryptographic primitives that incur substantial performance slowdown.  We present SGXDedup, which leverages Intel SGX to speed up encrypted deduplication based on server-aided message-locked encryption (MLE) while preserving security via SGX.  SGXDedup implements a suite of secure interfaces to execute MLE key generation and proof-of-ownership operations in SGX enclaves.  It also proposes various designs to support secure and efficient enclave operations.  Evaluation of synthetic and real-world workloads shows that SGXDedup achieves significant speedups and maintains high bandwidth and storage savings.

## Publication

* Yanjing Ren, Jingwei Li, Zuoru Yang, Patrick P. C. Lee, and Xiaosong Zhang. Accelerating Encrypted Deduplication via SGX. In Proc of USENIX Annual Technical Conference (ATC'21), July 2021.

## Prerequisites

SGXDedup is tested on a machine that equips with a Gigabyte B250M-D3H motherboard and an Intel i5-7400 CPU and runs Ubuntu 18.04.5 LTS.

Before running SGXDedup, check if your machine supports SGX. If there is an option as `SGX` or `Intel Software Guard Extensions` in BIOS, then enable the option; otherwise your machine does not support SGX.
We strongly recommend to find the SGX-supported device in the [SGX hardware list](https://github.com/ayeks/SGX-hardware).

### Registration

SGXDedup uses EPID-based remote attestation, and you need to register at the [EPID attestation page](https://api.portal.trustedservices.intel.com/EPID-attestation). Then, you can find your SPID and the corresponding subscription keys (both the primary and the secondary keys) at the [products page](https://api.portal.trustedservices.intel.com/products). Our test uses the `DEV Intel® Software Guard Extensions Attestation Service (Unlinkable)` product.


### Dependencies

SGXDedup depends on the following packages that  need to be installed manually or by package management tools.

1. Intel® Software Guard Extensions (Intel® SGX) driver version 2.6.0_4f5bb53 [Download](https://download.01.org/intel-sgx/sgx-linux/2.7/distro/ubuntu18.04-server/sgx_linux_x64_driver_2.6.0_4f5bb63.bin)
2. Intel® SGX platform software (Intel® SGX PSW) version 2.7.100.4 [Download](https://download.01.org/intel-sgx/sgx-linux/2.7/distro/ubuntu18.04-server/libsgx-enclave-common_2.7.100.4-bionic1_amd64.deb)
3. Intel® SGX SDK version 2.7.100.4 [Download](https://download.01.org/intel-sgx/sgx-linux/2.7/distro/ubuntu18.04-server/sgx_linux_x64_sdk_2.7.100.4.bin)
4. Intel® SGX SSL version lin_2.5_1.1.1d [Download](https://github.com/intel/intel-sgx-ssl/archive/refs/tags/lin_2.5_1.1.1d.zip)
5. OpenSSL version 1.1.1d [Donwload](https://www.openssl.org/source/old/1.1.1/openssl-1.1.1d.tar.gz)
6. The cmake module used to compile the SGX program in the cmake system: [Download](https://github.com/xzhangxa/SGX-CMake/blob/master/cmake/FindSGX.cmake)
7. libssl-dev (For SGXDedup encryption algorithm)
8. libcurl4-openssl-dev (Required by SGX packages)
9. libprotobuf-dev (Required by SGX packages)
10. libboost-all-dev (For SGXDedup multithreading, message transmission, etc.)
11. libleveldb-dev (For SGXDedup deduplication index based on LevelDB)
12. libsnappy-dev (Required by LevelDB)
13. build-essential (Basic program compilation environment)
14. cmake (CMake automated build framework)
15. wget (System components used for remote attestation requests)

We now provide a one-step script to automatically install and configure the dependencies. We have tested the script on Ubuntu 18.04 LTS.

```shell
chmod +x Scripts/environmentInstall.sh
sudo ./Scripts/environmentInstall.sh
```

Restart is required after the installation is finished. Then, check whether `isgx` is in `/dev`. If it is not in the directory (i.e., SGX driver is not successfully installed), reinstall SGX driver manually and restart the machine until `isgx` is in `/dev`.


## SGXDedup Running Guide

### Configuration

SGXDedup is configured based on JSON. You can change its configuration without rebuilding. We show the default configuration (`./config.json`) of SGXDedup as follows.

```json
{
    "ChunkerConfig": {
        "_chunkingType": 1, // 0: fixed size chunking; 1: variable size chunking; 2: FSL dataset hash list; 3: MS dataset hash list
        "_minChunkSize": 4096, // The smallest chunk size in variable size chunking, Uint: Byte (Maximum size 16KB)
        "_avgChunkSize": 8192, // The average chunk size in variable size chunking and chunk size in fixed size chunking, Uint: Byte (Maximum size 16KB)
        "_maxChunkSize": 16384, // The biggest chunk size in variable size chunking, Uint: Byte (Maximum size 16KB)
        "_slidingWinSize": 256, // The sliding window size in variable size chunking, Uint: MB
        "_ReadSize": 256 // System read input file size every I/O operation, Uint: MB
    },
    "KeyServerConfig": {
        "_keyBatchSize": 4096, // Maximum number of keys obtained per communication
        "_keyEnclaveThreadNumber": 1, // Maximum thread number for key enclave
        "_keyServerRArequestPort": 1559, // Key server host port for receive key enclave remote attestation request 
        "_keyServerIP": [
            "127.0.0.1"
        ], // Key server host IP ()
        "_keyServerPort": [
            6666
        ], // Key server host port for client key generation
        "_keyRegressionMaxTimes": 1048576, // Key regression maximum numbers `n`
        "_keyRegressionIntervals": 25920000 // Time interval for key regression (Unit: seconds), used for key enclave. Should be consistent with "server._keyRegressionIntervals"
    },
    "SPConfig": {
        "_storageServerIScriptsP": [
            "127.0.0.1"
        ], // Storage server host IP
        "_storageServerPort": [
            6668
        ], // Storage server host port for client upload or download files
        "_maxContainerSize": 8388608 // Maximum space for one-time persistent chunk storage, Uint: Byte (Maximum size 8MB)
    },
    "pow": {
        "_quoteType": 0, // Enclave quote type, do not modify it 
        "_iasVersion": 3, // Enclave IAS version, do not modify it 
        "_iasServerType": 0, // Server IAS version, do not modify it
        "_batchSize": 4096, // POW enclave batch size (Unit: chunks)
        "_ServerPort": 6669, // The port on storage server for remote attestation
        "_enclave_name": "pow_enclave.signed.so", // The enclave library name to create the target enclave
        "_SPID": "", // Your SPID for remote attseation service
        "_PriSubscriptionKey": "", // Your Intel remote attestation service primary subscription key
        "_SecSubscriptionKey": "" // Your Intel remote attestation service secondary subscription key
    },
    "km": {
        "_quoteType": 0, // Enclave quote type, do not modify it 
        "_iasVersion": 3, // Enclave IAS version, do not modify it 
        "_iasServerType": 0, // Server IAS version, do not modify it
        "_ServerPort": 6676, // The port on storage server for remote attestation
        "_enclave_name": "km_enclave.signed.so", // The enclave library name to create the target enclave
        "_SPID": "", // Your SPID for remote attseation service
        "_PriSubscriptionKey": "", // Your Intel remote attestation service primary subscription key
        "_SecSubscriptionKey": "" // Your Intel remote attestation service secondary subscription key
    },
    "server": {
        "_RecipeRootPath": "Recipes/", // Path to the file recipe storage directory
        "_containerRootPath": "Containers/", // Path to the unique chunk storage directory
        "_fp2ChunkDBName": "db1", // Path to the chunk database directory
        "_fp2MetaDBame": "db2" // Path to the file recipe database directory
        "_raSessionKeylifeSpan": 259200000 // Time interval for key regression (Unit: seconds), used for storage server. Should be consistent with "KeyServerConfig._keyRegressionIntervals"
    },
    "client": {
        "_clientID": 1, // Current client ID 
        "_sendChunkBatchSize": 1000, // Maximum number of chunks sent per communication
        "_sendRecipeBatchSize": 100000 // Maximum number of file recipe entry sent per communication
    }
}
```

Before starting, you need to fill the SPID and subscription keys in `./config.json` based on your registration information in Intel.

```json
...
"pow": {
    ...
    "_SPID": "", // Your SPID for remote attseation service
    "_PriSubscriptionKey": "", // Your Intel remote attestation service primary subscription key
    "_SecSubscriptionKey": "" // Your Intel remote attestation service secondary subscription key
},
"km": {
    ...
    "_SPID": "", // Your SPID for remote attseation service
    "_PriSubscriptionKey": "", // Your Intel remote attestation service primary subscription key
    "_SecSubscriptionKey": "" // Your Intel remote attestation service secondary subscription key
},
...
```

### Build

Compile SGXDedup as follows.

```shell
mkdir -p bin && mkdir -p build && mkdir -p lib && cd build
cmake -DCMAKE_BUILD_TYPE=Release .. && make

cd ..
cp lib/*.a bin/
cp ./lib/pow_enclave.signed.so ./bin
cp ./lib/km_enclave.signed.so ./bin
cp config.json bin/
cp -r key/ bin/
mkdir -p bin/Containers && mkdir -p bin/Recipes
```

Alternatively, we provide a script for a quick build and clean-up, and you can use it.

```shell
chmod +x ./Scripts/*.sh
# Build SGXDedup in release mode
./Scripts/buildReleaseMode.sh
# Build SGXDedup in debug mode
./Scripts/buildDebugMode.sh
# Clean up build result
./Scripts/cleanBuild.sh
```

### Usage

You can test SGXDedup in a single machine, and connect the key manager, server (e.g., the cloud in the ATC paper), and client instances via the local loopback interface.

```shell
# start cloud
./bin/server-sgx

# start key manager
./bin/keymanager-sgx
```

Since the key enclave  needs to be attested by the cloud before usage, you need to start the cloud (`server-sgx`) first, then start the key manager (`keymanager-sgx`), and wait for the message `KeyServer : keyServer session key update done` that indicates a successful attestation.

SGXDedup automatically verifies the PoW enclave by remote attestation in the first startup of the client, and by unsealing (Section 3.2 in the ATC paper) in the following startups. SGXDedup provides store and restores interfaces to clients.

```shell
# store file
./bin/client-sgx -s file

# restore file
./bin/client-sgx -r file
```

Note that we do not provide any commandline interface for renewing blinded key. Instead, you can configure `KeyServerConfig._keyRegressionIntervals` and `server._raSessionKeylifeSpan` (in the unit of a second) in `config.json` to set the time periods for key renewing cycle in the key manager and the cloud, respectively. Also, you can configure `_keyRegressionMaxTimes` to control the maximum number of key regression (2^20 by default).
