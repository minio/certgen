# certgen
`certgen` is a simple tool to generate self-signed certificates, and provides SAN certificates with DNS and IP entries.

## Install
Download [`certgen`](https://github.com/minio/certgen/releases/latest) for your specific operating system and platform.

## Example

```sh
certgen -ca -host "10.10.0.3,10.10.0.4,10.10.0.5"
```

A response similar to this one should be displayed:

```
2020/11/21 10:16:18 wrote public.crt
2020/11/21 10:16:18 wrote private.key
```
