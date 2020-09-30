package opstools

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2020 Panther Labs Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/hashicorp/go-cleanhttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
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

func SetUsage(banner string) {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(),
			"%s %s\nUsage:\n",
			filepath.Base(os.Args[0]), banner)
		flag.PrintDefaults()
	}
}
