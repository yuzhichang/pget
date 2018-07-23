package main

/**
Inspired by lftp's "pget -c -n".
Based on https://coderwall.com/p/uz2noa/fast-parallel-downloads-in-golang-with-accept-ranges-and-goroutines

https://tools.ietf.org/html/rfc7233#section-2.1
The first-byte-pos value in a byte-range-spec gives the byte-offset
of the first byte in a range.  The last-byte-pos value gives the
byte-offset of the last byte in the range; that is, the byte
positions specified are inclusive.  Byte offsets start at zero.

Example:
$ pget -c -n 3 ~/Downloads https://mirrors.aliyun.com/alpine/v3.8/releases/x86_64/alpine-minirootfs-3.8.0-x86_64.tar.gz alpine-minirootfs-3.8.0-x86_64.tar.gz.sha512

$ pget --debug -c -n 3 ~/Downloads http://mirrors.ustc.edu.cn/debian-cd/current/amd64/iso-cd/debian-9.5.0-amd64-netinst.iso SHA256SUMS
*/

import (
	"flag"
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/yuzhichang/pget"
)

func main() {
	var fileURL, ckmFileName, outDir string
	var maxconn int
	var cont bool
	var debug bool
	flag.BoolVar(&cont, "c", true, "continue download")
	flag.IntVar(&maxconn, "n", 1, "max connections")
	flag.BoolVar(&debug, "debug", false, "Set log level to DEBUG.")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "%s [-c] [-n maxconn] [--debug] outDir fileURL [ckmFileName]\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	// Initialize log
	formatter := &log.TextFormatter{
		FullTimestamp: true,
	}
	log.SetFormatter(formatter)
	if debug {
		log.SetLevel(log.DebugLevel)
	}

	args := flag.Args()
	if len(args) != 2 && len(args) != 3 {
		flag.Usage()
		return
	}
	outDir, fileURL = args[0], args[1]
	if len(args) == 3 {
		ckmFileName = args[2]
	}

	var getter *pget.PGet
	var err error
	if getter, err = pget.NewPGet(fileURL, ckmFileName, outDir, maxconn); err != nil {
		log.Fatalf("got error %+v", err)
	}
	if _, err := getter.DoParallel(cont); err != nil {
		log.Fatalf("got error %+v", err)
	}
}
