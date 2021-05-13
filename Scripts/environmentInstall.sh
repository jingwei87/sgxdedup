#!/bin/bash
# sudo apt update
# sudo apt dist-upgrade
# sudo apt autoremove
if [ ! -d "Packages" ]; then
  mkdir Packages
fi
sudo apt install build-essential cmake wget libssl-dev libcurl4-openssl-dev libprotobuf-dev libboost-all-dev libleveldb-dev libsnappy-dev
cd ./Packages/
echo "Download SGX Driver"
wget https://download.01.org/intel-sgx/sgx-linux/2.7/distro/ubuntu18.04-server/sgx_linux_x64_driver_2.6.0_4f5bb63.bin
echo "Download SGX SDK"
wget https://download.01.org/intel-sgx/sgx-linux/2.7/distro/ubuntu18.04-server/sgx_linux_x64_sdk_2.7.100.4.bin
echo "Download SGX PSW"
wget https://download.01.org/intel-sgx/sgx-linux/2.7/distro/ubuntu18.04-server/libsgx-enclave-common_2.7.100.4-bionic1_amd64.deb
echo "Download SGX SSL"
wget https://github.com/intel/intel-sgx-ssl/archive/refs/tags/lin_2.5_1.1.1d.zip
echo "Download OpenSSL for SGX SSL"
wget https://www.openssl.org/source/old/1.1.1/openssl-1.1.1d.tar.gz
echo "Download SGX CMake"
wget https://raw.githubusercontent.com/xzhangxa/SGX-CMake/master/cmake/FindSGX.cmake
cp FindSGX.cmake /usr/share/cmake-3.10/Modules/
chmod +x sgx_linux_x64_driver_2.6.0_4f5bb63.bin
sudo ./sgx_linux_x64_driver_2.6.0_4f5bb63.bin
sudo dpkg -i ./libsgx-enclave-common_2.7.100.4-bionic1_amd64.deb
chmod +x sgx_linux_x64_sdk_2.7.100.4.bin
sudo ./sgx_linux_x64_sdk_2.7.100.4.bin --prefix=/opt/intel
source /opt/intel/sgxsdk/environment
unzip lin_2.5_1.1.1d.zip
cp openssl-1.1.1d.tar.gz intel-sgx-ssl-lin_2.5_1.1.1d/openssl_source/
cd intel-sgx-ssl-lin_2.5_1.1.1d/Linux/
make all
make test
sudo make install
cd /opt/intel/sgxssl/include
sudo mv pthread.h sgxpthread.h
sudo sed -i '415c #include \"sgxpthread.h\"' /opt/intel/sgxssl/include/openssl/crypto.h
echo "Environment set done"
