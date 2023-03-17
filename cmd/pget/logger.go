package main

import (
	"os"
	"reflect"
	"regexp"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

var (
	logger       *zap.Logger
	logAtomLevel zap.AtomicLevel
	logPaths     []string
	fnPattern    *regexp.Regexp = regexp.MustCompile(`grpcio-(?P<ver>1\.41\.1|1\.42\.0|1\.43\.0)-cp(36|37|38|39|310|311|312)-.*-(manylinux_2_17_x86_64\.manylinux2014_x86_64|manylinux_2_17_aarch64)\.whl`)
)

func InitLogger(newLogPaths []string) {
	if reflect.DeepEqual(logPaths, newLogPaths) {
		return
	}
	logAtomLevel = zap.NewAtomicLevel()
	logPaths = newLogPaths
	var syncers []zapcore.WriteSyncer
	for _, p := range logPaths {
		switch p {
		case "stdout":
			syncers = append(syncers, zapcore.AddSync(os.Stdout))
		case "stderr":
			syncers = append(syncers, zapcore.AddSync(os.Stderr))
		default:
			writeFile := zapcore.AddSync(&lumberjack.Logger{
				Filename:   p,
				MaxSize:    100, // megabytes
				MaxBackups: 10,
				LocalTime:  true,
			})
			syncers = append(syncers, writeFile)
		}
	}

	cfg := zap.NewProductionEncoderConfig()
	cfg.EncodeTime = zapcore.ISO8601TimeEncoder
	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(cfg),
		zapcore.NewMultiWriteSyncer(syncers...),
		logAtomLevel,
	)
	logger = zap.New(core, zap.AddStacktrace(zap.ErrorLevel))
}

func SetLogLevel(newLogLevel string) {
	if logger != nil {
		var lvl zapcore.Level
		if err := lvl.Set(newLogLevel); err != nil {
			lvl = zap.InfoLevel
		}
		logAtomLevel.SetLevel(lvl)
	}
}
