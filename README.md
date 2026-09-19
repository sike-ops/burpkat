# burpkat

Combine an `ET_EXEC` host and a PIE (`ET_DYN`) payload into a single ELF. The
payload is grafted at a high load bias, its relocations are remapped against the
host's dynamic symbols, and a shellcode entry spawns the payload with
`pthread_create` before jumping to the host entry.

![pic](images/pic01.png)

## Build

```sh
cmake -B build
cmake --build build
```

## Usage

```sh
burpkat -i host -p payload -o output [-d]
```

Host must be non-PIE; payload must be PIE.

## Test

```sh
tests/cross/build.sh   # build host/payload against several glibc versions
tests/cross/run.sh     # run the host x payload matrix
```
