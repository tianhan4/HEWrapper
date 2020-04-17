## HEWrapper

This wrapper lets user to seamlessly use homomorphic encryption(HE) library, with limited change on origin code. It also provides an easy method to change the underlying HE scheme (although currently we only support [SEAL](https://github.com/microsoft/SEAL/tree/3.4.5)).

### How to use it
1. clone this repo and third party (SEAL)
```bash
git clone https://github.com/HydraZeng/HEWrapper.git
git submodule update --init --recursive
````
The following command run under `HEWrapper/hewrapper`.

2. build HEWrapper lib
```bash
make
```
`libhw.a` will be created under current dir.

3. build and run the example
```bash
make test
./seal_test
```
