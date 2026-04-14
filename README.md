# What the Hash!?
**What the Hash!?** is a simple hash reverse lookup. It searches a database of [270+](https://github.com/s0md3v/Bolt/blob/master/db/hashes.json) hash algorithms for the possible source of the given hash sum and outputs all found matches in [hashcat](https://hashcat.net/hashcat/) notation.

```console
go install go.foxforensics.dev/wth@latest
```

## Usage
```console
$ wth HASHSUM
```

## Acknowledgments
The hash algorithm database is based on parts of the [Bolt](https://github.com/s0md3v/Bolt) project from [Somdev Sangwan](https://github.com/s0md3v).

## License
Released under the [MIT License](LICENSE.md).