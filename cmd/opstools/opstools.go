package opstools

import (
	"github.com/hashicorp/go-cleanhttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"log"
	"net/http"
	"time"
)

func MustBuildLogger(debug bool) *zap.SugaredLogger {
	config := zap.NewDevelopmentConfig()
	// Always disable and file/line numbers, error traces and use color-coded log levels and short timestamps
	config.DisableCaller = true
	config.DisableStacktrace = true
	config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder

	if !debug {
		config.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	}
	logger, err := config.Build()
	if err != nil {
		log.Fatalf("failed to build logger: %s", err)
	}
	return logger.Sugar()
}

func NewHTTPClient(maxConnections int, timeout time.Duration) *http.Client {
	transport := cleanhttp.DefaultPooledTransport()
	transport.MaxIdleConnsPerHost = maxConnections
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
}
