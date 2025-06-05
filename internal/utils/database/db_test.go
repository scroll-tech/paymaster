package database

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/log"
	"github.com/mattn/go-colorable"
	"github.com/mattn/go-isatty"
)

func TestGormLogger(_ *testing.T) {
	output := io.Writer(os.Stderr)
	usecolor := (isatty.IsTerminal(os.Stderr.Fd()) || isatty.IsCygwinTerminal(os.Stderr.Fd())) && os.Getenv("TERM") != "dumb"
	if usecolor {
		output = colorable.NewColorableStderr()
	}

	opts := &slog.HandlerOptions{
		Level:     slog.LevelDebug,
		AddSource: true,
	}

	var handler slog.Handler
	if usecolor {
		handler = slog.NewTextHandler(output, opts)
	} else {
		handler = slog.NewTextHandler(output, opts)
	}

	logger := slog.New(handler)
	slog.SetDefault(logger)

	var gl gormLogger
	gl.gethLogger = log.Root()

	gl.Error(context.Background(), "test %s error:%v", "testError", errors.New("test error"))
	gl.Warn(context.Background(), "test %s warn:%v", "testWarn", errors.New("test warn"))
	gl.Info(context.Background(), "test %s warn:%v", "testInfo", errors.New("test info"))
	gl.Trace(context.Background(), time.Now(), func() (string, int64) { return "test trace", 1 }, nil)
}
