# rhash
Reverse hash lookup that searches a database of 270+ hash algorithms for the possible source of the given hash sum. All found matches will be output in [hashcat](https://hashcat.net/hashcat/) notation.

```console
go install go.foxforensics.eu/rhash@latest
```

## Usage
```console
$ rhash HASHSUM
```

## Acknowledgments
The hash algorithm database is based on parts of the [Bolt](https://github.com/s0md3v/Bolt) project by [Somdev Sangwan](https://github.com/s0md3v).

## License
Released under the [MIT License](LICENSE.md).