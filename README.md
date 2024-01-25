# certgen

`certgen` is a simple tool to generate self-signed certificates, and provides SAN certificates with DNS and IP entries.

## Install

<details open="true"><summary><b><a name="binary-releases">Binary Releases</a></b></summary>

| OS       | ARCH    | Binary                                                                                               |
|:--------:|:-------:|:----------------------------------------------------------------------------------------------------:|
| Linux    | amd64   | [linux-amd64](https://github.com/minio/certgen/releases/latest/download/certgen-linux-amd64)         |
| Linux    | arm64   | [linux-arm64](https://github.com/minio/certgen/releases/latest/download/certgen-linux-arm64)         |
| Linux    | ppc64le | [linux-ppc64le](https://github.com/minio/certgen/releases/latest/download/certgen-linux-ppc64le)     |
| Linux    | s390x   | [linux-s390x](https://github.com/minio/certgen/releases/latest/download/certgen-linux-s390x)         |
| Apple M1 | arm64   | [darwin-arm64](https://github.com/minio/certgen/releases/latest/download/certgen-darwin-arm64)       |
| Apple    | amd64   | [darwin-amd64](https://github.com/minio/certgen/releases/latest/download/certgen-darwin-amd64)       |
| Windows  | amd64   | [windows-amd64](https://github.com/minio/certgen/releases/latest/download/certgen-windows-amd64.exe) |
| Windows  | arm64   | [windows-amd64](https://github.com/minio/certgen/releases/latest/download/certgen-windows-arm64.exe) |
| FreeBSD  | amd64   | [freebsd-amd64](https://github.com/minio/certgen/releases/latest/download/certgen-freebsd-amd64)     |
| FreeBSD  | arm64   | [freebsd-amd64](https://github.com/minio/certgen/releases/latest/download/certgen-freebsd-arm64)     |

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
