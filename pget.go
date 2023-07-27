package pget

import (
	"context"
	"crypto"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/thanos-io/thanos/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/sync/semaphore"
)

const (
	BufSize   = 1 * 1024 * 1024
	MaxCntErr = 10
)

var (
	hashProgs = []string{"md5", "sha1", "sha256", "sha512"}
	// https://stuartleeks.com/posts/connection-re-use-in-golang-with-http-client/
	clientPool = sync.Pool{New: func() interface{} {
		return &http.Client{Transport: &http.Transport{IdleConnTimeout: 10 * time.Second}}
	}}
	pgSeq atomic.Int64
)

type PGet struct {
	fileURL     string
	ckmFileName string
	outDir      string
	maxconn     int
	logger      *zap.Logger
	sem         *semaphore.Weighted
	seq         int64
	wg          sync.WaitGroup
	fileURI     *url.URL
	filePath    string
	statusPath  string
	statusFile  *os.File
	statusData  []byte
}

func NewPGet(fileURL, ckmFileName, outDir string, maxconn int) (pg *PGet) {
	pg = &PGet{
		fileURL:     fileURL,
		ckmFileName: ckmFileName,
		outDir:      outDir,
		maxconn:     maxconn,
		logger:      zap.NewNop(),
		sem:         semaphore.NewWeighted(int64(maxconn)),
		seq:         pgSeq.Add(1),
	}
	return
}
func (pg *PGet) WithLogger(l *zap.Logger) *PGet {
	pg.logger = l
	return pg
}
func (pg *PGet) WithSemaphore(sem *semaphore.Weighted) *PGet {
	pg.sem = sem
	return pg
}

func (pg *PGet) prepareStatus() (err error) {
	if pg.statusFile, err = os.OpenFile(pg.statusPath, os.O_RDWR|os.O_CREATE, 0600); err != nil {
		err = errors.Wrapf(err, fmt.Sprintf("pg %d", pg.seq))
		return
	}
	var info os.FileInfo
	if info, err = pg.statusFile.Stat(); err != nil {
		err = errors.Wrapf(err, fmt.Sprintf("pg %d", pg.seq))
		return
	}
	if info.Size() != int64(24*pg.maxconn) {
		if err = pg.statusFile.Truncate(0); err != nil {
			err = errors.Wrapf(err, fmt.Sprintf("pg %d", pg.seq))
			return
		}
		var fileLen int
		if fileLen, err = pg.getFileLen(); err != nil {
			return
		}
		for i := 0; i < pg.maxconn; i++ {
			min := int64((fileLen / pg.maxconn) * i)       // Min range
			max := int64((fileLen / pg.maxconn) * (i + 1)) // Max range
			if i == pg.maxconn-1 {
				max = int64(fileLen) // Add the remaining bytes in the last request
			}
			offset := min
			binary.Write(pg.statusFile, binary.BigEndian, min)
			binary.Write(pg.statusFile, binary.BigEndian, max)
			binary.Write(pg.statusFile, binary.BigEndian, offset)
		}
	}
	if pg.statusData, err = FileMmap(pg.statusFile); err != nil {
		return
	}
	return
}

func (pg *PGet) doneStatus() (err error) {
	err = FileMunmap(pg.statusData)
	pg.statusFile.Close()
	os.Remove(pg.statusPath)
	return
}

func (pg *PGet) expectChecksum() (hashProg, ckm string, err error) {
	// checksum can be encoded in url fragment
	if pg.fileURI.Fragment != "" {
		kv := strings.Split(pg.fileURI.Fragment, "=")
		if len(kv) == 2 {
			for _, prog := range hashProgs {
				if prog == kv[0] {
					hashProg = prog
					ckm = kv[1]
					return
				}
			}
		}
	}
	// download and parse checksum file
	if pg.ckmFileName == "" {
		return
	}
	suffix := filepath.Ext(strings.ToLower(pg.ckmFileName))
	if len(suffix) <= 1 {
		err = errors.Newf("pg %d checksum file name %s is invalid", pg.seq, pg.ckmFileName)
		return
	}
	suffix = suffix[1:]
	for _, prog := range hashProgs {
		if suffix == prog {
			hashProg = prog
			break
		}
	}
	if hashProg == "" {
		err = errors.Newf("pg %d checksum file name %s is invalid", pg.seq, pg.ckmFileName)
		return
	}
	ckmURL := *pg.fileURI
	ckmURL.Path = filepath.Join(filepath.Dir(pg.fileURI.Path), pg.ckmFileName)
	fileName := filepath.Base(pg.filePath)

	client := clientPool.Get().(*http.Client)
	defer clientPool.Put(client)
	resp, err := client.Get(ckmURL.String())
	if err != nil {
		err = errors.Wrapf(err, "")
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		err = errors.Newf("pg %d resp.StatusCode=%d is unexpected", pg.seq, resp.StatusCode)
		return

	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		err = errors.Wrapf(err, fmt.Sprintf("pg %d", pg.seq))
		return
	}
	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		switch len(fields) {
		case 1:
			ckm = fields[0]
		case 2:
			if fields[1][0] == '*' {
				fields[1] = fields[1][1:]
			}
			if fields[1] == fileName {
				ckm = fields[0]
			}
		}
		if ckm != "" {
			break
		}
	}
	if ckm == "" {
		err = errors.Newf("pg %d could not locate checksum for %s in %s", pg.seq, pg.fileURL, ckmURL.String())
		return
	}
	return
}

func (pg *PGet) calcChecksum(hash string) (ckm string, err error) {
	var h crypto.Hash
	switch hash {
	case "md5":
		h = crypto.MD5
	case "sha1":
		h = crypto.SHA1
	case "sha256":
		h = crypto.SHA256
	case "sha512":
		h = crypto.SHA512
	default:
		err = errors.Newf("pg %d unsupported hash program %s", pg.seq, hash)
		return
	}
	hasher := h.New()
	var f2 *os.File
	if f2, err = os.Open(pg.filePath); err != nil {
		err = errors.Wrapf(err, fmt.Sprintf("pg %d", pg.seq))
		return
	}
	defer f2.Close()
	if _, err = io.Copy(hasher, f2); err != nil {
		err = errors.Wrapf(err, fmt.Sprintf("pg %d", pg.seq))
		return
	}
	ckm = hex.EncodeToString(hasher.Sum(nil))
	return
}

func (pg *PGet) getFileLen() (length int, err error) {
	client := clientPool.Get().(*http.Client)
	defer clientPool.Put(client)
	res, err := client.Head(pg.fileURI.String())
	if err != nil {
		err = errors.Wrapf(err, fmt.Sprintf("pg %d", pg.seq))
		return
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		err = errors.Newf("pg %d res.StatusCode=%d is unexpected", pg.seq, res.StatusCode)
		return
	}
	maps := res.Header
	if length, err = strconv.Atoi(maps["Content-Length"][0]); err != nil {
		err = errors.Wrapf(err, "")
		return
	}
	return
}

func (pg *PGet) DoParallel(ctx context.Context, cont bool) (filePath string, err error) {
	if pg.fileURI, err = url.Parse(pg.fileURL); err != nil {
		err = errors.Wrapf(err, fmt.Sprintf("pg %d", pg.seq))
		return
	}
	fileName := filepath.Base(pg.fileURI.Path)
	pg.filePath = filepath.Join(pg.outDir, fileName)
	pg.statusPath = filepath.Join(pg.outDir, fmt.Sprintf("%s.pget-status", fileName))
	filePath = pg.filePath
	// skip downloading if the file already exists and the checksum match
	var hashProg, expCkm, actCkm string
	if hashProg, expCkm, err = pg.expectChecksum(); err != nil {
		return
	}
	pg.logger.Debug("expectChecksum", zap.Int64("pg", pg.seq), zap.String("filePath", pg.filePath), zap.String("hashProg", hashProg), zap.String("expCkm", expCkm))
	if expCkm != "" {
		if actCkm, err = pg.calcChecksum(hashProg); err == nil && actCkm == expCkm {
			pg.logger.Debug("checksum match, skip downloading", zap.Int64("pg", pg.seq))
			return
		}
		pg.logger.Debug("checksum mismatch", zap.Int64("pg", pg.seq), zap.String("actCkm", actCkm), zap.String("expCkm", expCkm))
	}

	// download file
	var flag int
	var fileLen int
	if cont {
		if err = pg.prepareStatus(); err != nil {
			return
		}
		flag = os.O_WRONLY | os.O_CREATE
	} else {
		flag = os.O_WRONLY | os.O_TRUNC | os.O_CREATE
		if fileLen, err = pg.getFileLen(); err != nil {
			return
		}
	}

	var f *os.File
	f, err = os.OpenFile(pg.filePath, flag, 0600)
	if err != nil {
		err = errors.Wrapf(err, "")
		return
	}
	defer f.Close()

	errCh := make(chan error, pg.maxconn*MaxCntErr)
	for i := 0; i < pg.maxconn; i++ {
		pg.wg.Add(1)
		if err = pg.sem.Acquire(context.Background(), 1); err != nil {
			err = errors.Wrapf(err, "pg %d failed to acquire semaphore", pg.seq)
			return
		}

		go func(i int, errCh chan error) {
			var err error
			var n int
			var min, max, off int64
			defer pg.wg.Done()
			defer pg.sem.Release(1)
			if cont {
				min = int64(binary.BigEndian.Uint64(pg.statusData[24*i:]))
				max = int64(binary.BigEndian.Uint64(pg.statusData[24*i+8:]))
				off = int64(binary.BigEndian.Uint64(pg.statusData[24*i+16:]))
			} else {
				min = int64((fileLen / pg.maxconn) * i)       // Min range
				max = int64((fileLen / pg.maxconn) * (i + 1)) // Max range
				if i == pg.maxconn-1 {
					max = int64(fileLen) // Add the remaining bytes in the last request
				}
				off = min
			}
			pg.logger.Debug("thread begin", zap.Int64("pg", pg.seq), zap.Int("thread", i), zap.Int64("max", max), zap.Int64("off", off), zap.Int64("remained", max-off))
			buf := make([]byte, BufSize, BufSize)
			var cntErr int
			client := clientPool.Get().(*http.Client)
			defer clientPool.Put(client)
			for off < max && cntErr < MaxCntErr {
				min = off
				req, _ := http.NewRequest("GET", pg.fileURL, nil)
				req = req.WithContext(ctx)
				rangeHeader := fmt.Sprintf("bytes=%d-%d", off, max-1)
				pg.logger.Debug("thread GET", zap.Int64("pg", pg.seq), zap.Int("thread", i), zap.String("range", rangeHeader))
				req.Header.Add("Range", rangeHeader)
				resp, err := client.Do(req)
				if err != nil {
					err = errors.Wrapf(err, fmt.Sprintf("pg %d, thread %d", pg.seq, i))
					errCh <- err
					cntErr++
					if cntErr >= MaxCntErr {
						goto QUIT
					} else {
						goto CONT
					}
				}
				pg.logger.Debug("thread GET response", zap.Int64("pg", pg.seq), zap.Int("thread", i), zap.Int("status code", resp.StatusCode), zap.Any("header", resp.Header))
				if resp.StatusCode == 429 {
					// https://httpstatuses.com/429
					wait := 10
					if waitStr := resp.Header.Get("Retry-After"); waitStr != "" {
						if wait2, err2 := strconv.Atoi(waitStr); err2 == nil {
							wait = wait2
						}
					}
					err = errors.Newf("pg %d, thread %d, Retry-After %d s", pg.seq, i, wait)
					errCh <- err
					cntErr++
					if cntErr >= MaxCntErr {
						goto QUIT
					} else {
						time.Sleep(time.Duration(wait) * time.Second)
						goto CONT
					}
				} else if resp.StatusCode != 206 {
					// Go already handled redirection. http://colobu.com/2017/04/19/go-http-redirect/
					err = errors.Newf("pg %d, thread %d, status code %d", pg.seq, i, resp.StatusCode)
					errCh <- err
					cntErr++
					if cntErr >= MaxCntErr {
						goto QUIT
					} else {
						goto CONT
					}
				}

				for {
					n = 0
					n, err = resp.Body.Read(buf)
					if n > 0 {
						if _, err = f.WriteAt(buf[:n], off); err != nil {
							err = errors.Wrapf(err, fmt.Sprintf("pg %d, thread %d", pg.seq, i))
							goto QUIT
						}
					}
					off += int64(n)
					if cont {
						binary.BigEndian.PutUint64(pg.statusData[24*i+16:], uint64(off))
					}
					if off >= max {
						err = nil
						break
					}
					if err != nil {
						err = errors.Wrapf(err, "pg %d, thread %d", pg.seq, i)
						pg.logger.Warn("thread got error", zap.Int64("pg", pg.seq), zap.Int("thread", i), zap.Int("code", resp.StatusCode), zap.Error(err), zap.Int64("written", off-min))
						cntErr++
						if cntErr >= MaxCntErr {
							goto QUIT
						} else {
							break
						}
					}
				}
			CONT:
				if resp != nil {
					resp.Body.Close()
				}
			}
		QUIT:
			pg.logger.Debug("thread end", zap.Int64("pg", pg.seq), zap.Int("thread", i), zap.Int64("max", max), zap.Int64("off", off), zap.Int64("remained", max-off), zap.Error(err))
		}(i, errCh)
	}

	pg.wg.Wait()
	close(errCh)
	var taskErr error
	for err = range errCh {
		if err != nil {
			taskErr = err
		}
	}
	if taskErr != nil {
		err = taskErr
		return
	}
	if cont {
		if err = pg.doneStatus(); err != nil {
			return
		}
	}

	// Verify checksum
	if expCkm != "" {
		if actCkm, err = pg.calcChecksum(hashProg); err != nil {
			return
		}
		if actCkm != expCkm {
			err = errors.Newf("pg %d checksum mismatch, have %v, want %v", pg.seq, actCkm, expCkm)
			return
		}
	}
	pg.logger.Info("done downloading", zap.Int64("pg", pg.seq), zap.String("filePath", pg.filePath))
	return
}

type MGet struct {
	fileURLs     []string
	ckmFileNames []string
	outDir       string
	maxconn      int
	logger       *zap.Logger
	semPg        *semaphore.Weighted
	semTask      *semaphore.Weighted
}

func NewMGet(fileURLs, ckmFileNames []string, outDir string, maxconn int) (mg *MGet) {
	mg = &MGet{
		fileURLs:     fileURLs,
		ckmFileNames: ckmFileNames,
		outDir:       outDir,
		maxconn:      maxconn,
		logger:       zap.NewNop(),
		semPg:        semaphore.NewWeighted(int64(maxconn)),
		semTask:      semaphore.NewWeighted(int64(maxconn)),
	}
	return
}
func (mg *MGet) WithLogger(l *zap.Logger) *MGet {
	mg.logger = l
	return mg
}
func (mg *MGet) DoParallel(ctx context.Context, cont bool) (filePaths []string, err error) {
	var wg sync.WaitGroup
	fpCh := make(chan string, len(mg.fileURLs))
	errCh := make(chan error, len(mg.fileURLs))
	for i, fileURL := range mg.fileURLs {
		var ckmFileName string
		if len(mg.ckmFileNames) > i {
			ckmFileName = mg.ckmFileNames[i]
		}
		wg.Add(1)
		if err = mg.semPg.Acquire(ctx, 1); err != nil {
			err = errors.Wrapf(err, "failed to acquire semaphore")
			return
		}
		go func(fileURL, ckmFileName string) {
			defer wg.Done()
			defer mg.semPg.Release(1)
			var filePath string
			if filePath, err = NewPGet(fileURL, ckmFileName, mg.outDir, mg.maxconn).WithLogger(mg.logger).WithSemaphore(mg.semTask).DoParallel(ctx, cont); err != nil {
				errCh <- err
				return
			}
			fpCh <- filePath
		}(fileURL, ckmFileName)
	}
	wg.Wait()
FOR:
	for {
		select {
		case filePath := <-fpCh:
			filePaths = append(filePaths, filePath)
		case err2 := <-errCh:
			err = err2
		default:
			break FOR
		}
	}
	if err != nil {
		return
	}
	sort.Strings(filePaths)
	return
}
