# pget

Parallel, continuable HTTP/HTTPS download tool, inspired by lftp's "pget -c -n" and "mget -n".

Usage:

```
$ pget -h
Parallel, continuable HTTP/HTTPS download tool, inspired by lftp's "pget -c -n" and "mget -n".
Requires the website support the "Range" header(https://www.rfc-editor.org/rfc/rfc7233#section-3.1).
Homepage: https://github.com/yuzhichang/pget

pget [-d] [-n maxconn] [-O <base>] <file_urls> [checksum_files]
file_urls       comma-separated http or https urls
checksum_files  comma-separated checksum files name, empty one means the checksum is encoded as url segment, or not provided
  -O string
        base directory where files should be placed, default is current directory (default ".")
  -d    Set log level to DEBUG.
  -n int
        max connections (default 5)
```

Example:

```
$ pget https://mirrors.aliyun.com/alpine/v3.8/releases/x86_64/alpine-minirootfs-3.8.0-x86_64.tar.gz alpine-minirootfs-3.8.0-x86_64.tar.gz.sha512
$ pget http://mirrors.ustc.edu.cn/debian-cd/current/amd64/iso-cd/debian-9.5.0-amd64-netinst.iso SHA256SUMS
$ pget https://pypi.tuna.tsinghua.edu.cn/packages/58/0a/2ba9c2ae852f2b03b3fba0c8815158809d0f8b4b699d212f85cb065efc96/grpcio-1.51.3-cp310-cp310-manylinux_2_17_x86_64.manylinux2014_x86_64.whl#sha256=3709048fe0aa23dda09b3e69849a12055790171dab9e399a72ea8f9dfbf9ac80,https://pypi.tuna.tsinghua.edu.cn/packages/8b/ba/a0994523e2dd3d6747ef1dc9458aba8c907953bed062f809fcbdd5f32020/grpcio-1.51.3-cp310-cp310-manylinux_2_17_aarch64.whl#sha256=82b0ad8ac825d4bb31bff9f638557c045f4a6d824d84b21e893968286f88246b
```

# Installation

Please use the following steps to build and install pget on Linux.

```
$ go install github.com/yuzhichang/pget/cmd/pget@latest
```

# Build from source

Checkout code, run following to build.
```
$ go build -o . ./...
```
