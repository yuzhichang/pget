package pget

import (
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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

const (
	BufSize   = 1 * 1024 * 1024
	MaxCntErr = 10
)

type PGet struct {
	FileURL     *url.URL
	CkmFileName string
	OutDir      string
	MaxConn     int
	wg          sync.WaitGroup
	filePath    string
	statusPath  string
	statusFile  *os.File
	statusData  []byte
}

func NewPGet(fileURL, ckmFileName, outDir string, maxconn int) (pg *PGet, err error) {
	pg = &PGet{
		CkmFileName: ckmFileName,
		OutDir:      outDir,
		MaxConn:     maxconn,
	}
	if pg.FileURL, err = pg.FileURL.Parse(fileURL); err != nil {
		return
	}
	fileName := filepath.Base(pg.FileURL.Path)
	pg.filePath = filepath.Join(outDir, fileName)
	pg.statusPath = filepath.Join(outDir, fmt.Sprintf("%s.pget-status", fileName))
	return
}

func (pg *PGet) prepareStatus() (err error) {
	if pg.statusFile, err = os.OpenFile(pg.statusPath, os.O_RDWR|os.O_CREATE, 0600); err != nil {
		return
	}
	var info os.FileInfo
	if info, err = pg.statusFile.Stat(); err != nil {
		return
	}
	if info.Size() != int64(24*pg.MaxConn) {
		if err = pg.statusFile.Truncate(0); err != nil {
			return
		}
		var fileLen int
		if fileLen, err = pg.getFileLen(); err != nil {
			return
		}
		for i := 0; i < pg.MaxConn; i++ {
			min := int64((fileLen / pg.MaxConn) * i)       // Min range
			max := int64((fileLen / pg.MaxConn) * (i + 1)) // Max range
			if i == pg.MaxConn-1 {
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

// download and parse checksum file
func (pg *PGet) getChecksum() (ckm string, err error) {
	ckmURL := *pg.FileURL
	ckmURL.Path = filepath.Join(filepath.Dir(pg.FileURL.Path), pg.CkmFileName)
	fileName := filepath.Base(pg.filePath)

	resp, err := http.Get(ckmURL.String())
	if err != nil {
		err = errors.Wrapf(err, "")
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		err = errors.Errorf("resp.StatusCode=%d is unexpected", resp.StatusCode)
		return

	}

	body, err := ioutil.ReadAll(resp.Body)
	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[1] == fileName {
			ckm = fields[0]
		}
	}
	if ckm == "" {
		err = errors.Errorf("could not locate checksum for %s in %s", pg.FileURL.String(), ckmURL.String())
		log.Debugf("checksum file: %v", string(body))
		return
	}
	return
}

func (pg *PGet) calcChecksum() (ckm string, err error) {
	ckmFileName := strings.ToLower(pg.CkmFileName)
	var h crypto.Hash
	if strings.Index(ckmFileName, "md5") >= 0 {
		h = crypto.MD5
	} else if strings.Index(ckmFileName, "sha512") >= 0 {
		h = crypto.SHA512
	} else if strings.Index(ckmFileName, "sha256") >= 0 {
		h = crypto.SHA256
	} else if strings.Index(ckmFileName, "sha1") >= 0 {
		h = crypto.SHA1
	} else {
		err = errors.Errorf("unsupported checksum %s", ckmFileName)
		return
	}
	hasher := h.New()
	var f2 *os.File
	if f2, err = os.Open(pg.filePath); err != nil {
		err = errors.Wrapf(err, "")
		return
	}
	defer f2.Close()
	if _, err = io.Copy(hasher, f2); err != nil {
		err = errors.Wrapf(err, "")
		return
	}
	ckm = hex.EncodeToString(hasher.Sum(nil))
	return
}

func (pg *PGet) getFileLen() (length int, err error) {
	res, err := http.Head(pg.FileURL.String())
	if err != nil {
		err = errors.Wrapf(err, "")
		return
	}
	maps := res.Header
	if length, err = strconv.Atoi(maps["Content-Length"][0]); err != nil {
		err = errors.Wrapf(err, "")
		return
	}
	return
}

func (pg *PGet) DoParallel(cont bool) (err error) {
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

	errCh := make(chan error, pg.MaxConn)
	for i := 0; i < pg.MaxConn; i++ {
		pg.wg.Add(1)

		go func(i int, errCh chan error) {
			var err error
			var n int
			var min, max, off int64
			if cont {
				min = int64(binary.BigEndian.Uint64(pg.statusData[24*i:]))
				max = int64(binary.BigEndian.Uint64(pg.statusData[24*i+8:]))
				off = int64(binary.BigEndian.Uint64(pg.statusData[24*i+16:]))
			} else {
				min = int64((fileLen / pg.MaxConn) * i)       // Min range
				max = int64((fileLen / pg.MaxConn) * (i + 1)) // Max range
				if i == pg.MaxConn-1 {
					max = int64(fileLen) // Add the remaining bytes in the last request
				}
				off = min
			}
			log.Debugf("thread %d, min %d, max %d, off %d", i, min, max, off)
			buf := make([]byte, BufSize, BufSize)
			var cntErr int
			client := &http.Client{}
			for off < max && cntErr < MaxCntErr {
				min = off
				req, _ := http.NewRequest("GET", pg.FileURL.String(), nil)
				rangeHeader := fmt.Sprintf("bytes=%d-%d", off, max-1)
				log.Debugf("thread %d, %s", i, rangeHeader)
				req.Header.Add("Range", rangeHeader)
				resp, err := client.Do(req)
				if err != nil {
					err = errors.Wrapf(err, "")
					cntErr++
					if cntErr >= MaxCntErr {
						goto QUIT
					} else {
						continue
					}
				}
				defer resp.Body.Close()
				if resp.StatusCode == 429 {
					// https://httpstatuses.com/429
					wait := 3600
					waitStr := resp.Header.Get("Retry-After")
					if waitStr != "" {
						wait, err = strconv.Atoi(waitStr)
						cntErr++
						if cntErr >= MaxCntErr {
							goto QUIT
						} else {
							continue
						}
					}
					log.Debugf("thread %d, Retry-After %s", i, waitStr)
					time.Sleep(time.Duration(wait) * time.Microsecond)
					continue
				} else if resp.StatusCode != 206 {
					// Go already handled redirection. http://colobu.com/2017/04/19/go-http-redirect/
					log.Errorf("resp.StatusCode=%d is unexpected!", resp.StatusCode)
					cntErr++
					if cntErr >= MaxCntErr {
						goto QUIT
					} else {
						continue
					}
				}

				for {
					n = 0
					n, err = resp.Body.Read(buf)
					if n > 0 {
						if _, err = f.WriteAt(buf[:n], off); err != nil {
							err = errors.Wrapf(err, "")
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
						err = errors.Wrapf(err, "")
						log.Debugf("resp.StatusCode=%d, n=%d, written=%d, err=%+v", resp.StatusCode, n, off-min, err)
						cntErr++
						if cntErr >= MaxCntErr {
							goto QUIT
						} else {
							break
						}
					}
				}
			}
		QUIT:
			if err != nil {
				errCh <- err
			}
			pg.wg.Done()
		}(i, errCh)
	}

	// Download checksum file
	var ckm, ckm2 string
	if pg.CkmFileName != "" {
		if ckm, err = pg.getChecksum(); err != nil {
			return
		}
	}

	pg.wg.Wait()
	close(errCh)
	var taskErr error
	for err = range errCh {
		taskErr = err
		log.Errorf("a thread got fatal error %+v", err)
	}
	if taskErr != nil {
		return taskErr
	}
	if cont {
		if err = pg.doneStatus(); err != nil {
			return
		}
	}

	// Verify checksum
	if pg.CkmFileName != "" {
		if ckm2, err = pg.calcChecksum(); err != nil {
			return
		}
		if ckm != ckm2 {
			err = errors.Errorf("checksum mismatch, have %v, want %v", ckm2, ckm)
			return
		}
	}

	return
}
