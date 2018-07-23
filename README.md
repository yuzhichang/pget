# pget

Parallel, continuable HTTP download tool, inspired by lftp's "pget -c -n".

Example:

```
$ pget -c -n 3 ~/Downloads https://mirrors.aliyun.com/alpine/v3.8/releases/x86_64/alpine-minirootfs-3.8.0-x86_64.tar.gz alpine-minirootfs-3.8.0-x86_64.tar.gz.sha512

$ pget --debug -c -n 3 ~/Downloads http://mirrors.ustc.edu.cn/debian-cd/current/amd64/iso-cd/debian-9.5.0-amd64-netinst.iso SHA256SUMS
```

# Installation

Please use the following steps to build and install pget on Linux.

There are two ways to install. First is the standard `go get` method:

```
go get -u github.com/yuzhichang/pget/cmd/pget
```

Alternatively make sure $GOPATH is set and:

```
$ git clone https://github.com/yuzhichang/pget $GOPATH/src/github.com/yuzhichang/pget
$ cd $GOPATH/src/github.com/yuzhichang/pget/cmd/pget
$ go install .
```
