<!--
 This file is Free Software under the Apache-2.0 License
 without warranty, see README.md and LICENSES/Apache-2.0.txt for details.

 SPDX-License-Identifier: Apache-2.0

 SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
 Software-Engineering: 2026 Intevation GmbH <https://intevation.de>
-->

# forwardertarget

A little web server offering a demo endpoint for the forwarding
logic used in [csaf_downloader](https://github.com/gocsaf/csaf/blob/main/docs/csaf_downloader.md#forwarding) and [ISDuBA](https://github.com/ISDuBA/ISDuBA/blob/main/docs/forwarder.md).

An earlier Java based endpoint can be found [here](https://github.com/mfd2007/csaf_upload_interface/).

## Howto build

You need at least [Go 1.25](https://go.dev/dl/) to compile it.

```
git clone https://github.com/gocsaf/forwardertarget.git
cd forwardertarget
go build
```

Place the resulting `forwardertarget` binary into your `PATH`.

## Usage

```
$ forwardertarget --help
Usage of forwardertarget:
  -h string
    	host of the forward target (shorthand) (default "localhost")
  -host string
    	host of the forward target (default "localhost")
  -m int
    	max upload size (shorthand) (default 536871936)
  -maxupload int
    	max upload size in bytes (default 536871936)
  -p int
    	port of the forward target (shorthand) (default 8888)
  -port int
    	port of the forward target (default 8888)
  -s string
    	SQLite3 database to store documents in
  -store string
    	SQLite3 database to store documents in
```

Starting **forwardertarget** with its default arguments will bind
the web server to localhost port 8888. Forwarded documents
up to 512 MiB (+1 KiB metadata) will be accepted by the endpoint.

A simple example how to send advisories to this endpoint
via [curl](https://curl.se/) can be found [here](./contrib/upload.sh).

```
$ wget https://raw.githubusercontent.com/oasis-tcs/csaf/refs/heads/master/csaf_2.0/examples/csaf/bsi-2022-0001.json
$ ./contrib/upload.sh bsi-2022-0001.json
```

By default **forwardertarget** only consumes the uploaded documents.
With the `-s|--store` flag you can tell it to store the documents
in a [SQLite3](https://sqlite.org/) database. The database file
will be created at start if it does not exist.

```
CREATE TABLE documents (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  filename          text,
  publisher         text,
  tracking_id       text,
  validation_status text,
  original          BLOB NOT NULL
);
CREATE TABLE sqlite_sequence(name,seq);
```

Running **forwardertarget** in this mode is useful for statistical and
archiving purposes.

To save space the advisories are store in [Zstandard](https://facebook.github.io/zstd/) form.

If you want to extract the original files you can do something like this:

```
$ mkdir bsi_advisories
$ sqlite3 documents.sqlite
sqlite> SELECT writefile(concat('bsi_advisories/', id, '-', coalesce(filename, 'document.json'), '.zst'), original) FROM documents WHERE publisher = 'Bundesamt für Sicherheit in der Informationstechnik';
.quit
$ cd bsi_advisories
$ zstd -d --rm *.zst
```

This will leave the uncompressed JSON files of the publisher "Bundesamt für Sicherheit in der Informationstechnik" in the folder `bsi_advisories`.

## License

**forwardertarget** is Free Software.

Source code written for **forwardertarget** was placed under the
[Apache License, Version 2.0](./LICENSE).

```
 SPDX-License-Identifier: Apache-2.0

 SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
 Software-Engineering: 2026 Intevation GmbH <https://intevation.de>
```

forwardertarget depends on third party Free Software components which have their
own right holders and licenses. To our best knowledge
(at the time when they were added)
the dependencies are upwards compatible with the forwardertarget main license.
