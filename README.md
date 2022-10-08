# ACME client

## Run

For local development start a pebble server:

```bash
./pebble/run
```

Then add the following to your `/etc/hosts`

```plain
127.0.0.1 example.com
```

To run the ACME client to issue and install a certificate:

```bash
go run ./src http01 --dir https://localhost:14000/dir --record 127.0.0.1 --domain example.com
```

To verify that it worked visit https://localhost:5001 or run:

```bash
openssl s_client -showcerts -connect example.com:5001 </dev/null
```
