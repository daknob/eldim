# eldim decypt tool

The `decrypt` tool of eldim is used to decrypt data that have been encrypted
during upload. It cannot download data from the various backends, it reads
the files from the local file system, so you need to download them before
using it.

## Usage
Using `decrypt` is really simple. After you have the `decrypt` binary, just
run `decrypt -h` to see some help information:

```
$ decrypt -h
Usage of decrypt:
  -in string
        The encrypted file to decrypt. (default "input.dat")
  -key string
        The encryption password to decrypt the data. (default "Insecure")
  -out string
        The file to save the decrypted data. (default "output.dat")
```

There are three command line flags, and all three are **required** for the
tool to work. They are explained here:

### in
The `in` argument contains the path to the encrypted file, that needs to be
decrypted by `decrypt`.

### out
The `out` argument contains the path to the output file of `decrypt`, which
will be the plaintext file.

### key
The `key` argument is the encryption password / key used and configured in
eldim during the encryption phase, inside `eldim.yml`.

## Logging
Currently `decrypt` logs a bit of information so you can know what is going
on, as well as how much time it takes for various operations. It has been
designed to log some unique parameters of each run, such as the input and
output file, so when used in a script with many files, you can then have
usable logs of what happened in each decryption.