# certgen

`certgen` is a simple tool to generate self-signed certificates, and provides SAN certificates with DNS and IP entries.

## Install

Download [`certgen`](https://github.com/minio/certgen/releases/latest) for your specific operating system and platform.

## Example (server)

```sh
certgen -host "127.0.0.1,localhost"

Created a new certificate 'public.crt', 'private.key' valid for the following names 📜
 - "127.0.0.1"
 - "localhost"
```

## Example (client)

```sh
certgen -client -host "localhost"

Created a new certificate 'client.crt', 'client.key' valid for the following names 📜
 - "localhost"
```
