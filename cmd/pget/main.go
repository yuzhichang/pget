package main

/**
Inspired by lftp's "pget -c -n" and "mget -c".
Based on https://coderwall.com/p/uz2noa/fast-parallel-downloads-in-golang-with-accept-ranges-and-goroutines

https://tools.ietf.org/html/rfc7233#section-2.1
The first-byte-pos value in a byte-range-spec gives the byte-offset
of the first byte in a range.  The last-byte-pos value gives the
byte-offset of the last byte in the range; that is, the byte
positions specified are inclusive.  Byte offsets start at zero.
*/

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/yuzhichang/pget"
	"go.uber.org/zap"
)

const (
	usage = `Parallel, continuable HTTP/HTTPS download tool, inspired by lftp's "pget -c -n" and "mget -n".
Requires the website support the "Range" header(https://www.rfc-editor.org/rfc/rfc7233#section-3.1).
Homepage: https://github.com/yuzhichang/pget

pget [-d] [-n maxconn] [-O <base>] <file_urls> [checksum_files]
file_urls       comma-separated http or https urls
checksum_files  comma-separated checksum files name, empty one means the checksum is encoded as url segment, or not provided`
)

func main() {
	maxconn := 5
	debug := false
	outDir := "."
	var file_urls, checksum_files string
	flag.IntVar(&maxconn, "n", maxconn, "max connections")
	flag.BoolVar(&debug, "d", debug, "Set log level to DEBUG.")
	flag.StringVar(&outDir, "O", outDir, "base directory where files should be placed, default is current directory")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, usage)
		flag.PrintDefaults()
	}
	flag.Parse()
	args := flag.Args()
	if len(args) == 1 {
		file_urls = args[0]
	} else if len(args) == 2 {
		file_urls = args[0]
		checksum_files = args[1]
	} else {
		fmt.Fprintf(os.Stderr, "the number of arguments is invalid, want 1 or 2, have %d\n", len(args))
		flag.Usage()
		return
	}

	InitLogger([]string{"stdout"})
	if debug {
		SetLogLevel("debug")
	} else {
		SetLogLevel("info")
	}

	urls := strings.Split(file_urls, ",")
	ckms := strings.Split(checksum_files, ",")
	logger.Info("going to download", zap.Strings("urls", urls), zap.Strings("ckms", ckms))
	ctx := context.Background()
	var filePaths []string
	var err error
	if filePaths, err = pget.NewMGet(urls, ckms, outDir, maxconn).WithLogger(logger).DoParallel(ctx, true); err != nil {
		logger.Error("pget failed", zap.Error(err))
		return
	}
	logger.Info("pget filePaths", zap.Strings("filePaths", filePaths))
}
