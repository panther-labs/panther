package mage

/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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
	"log"
	"time"

	"github.com/magefile/mage/mg"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var logger *zap.SugaredLogger

// serializes a time.Time to just hour:minute:second
func simpleTimeEncoder(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
	enc.AppendString(t.Format("15:04:05"))
}

// Build the global zap logger
func init() {
	config := zap.NewDevelopmentConfig() // DEBUG by default
	if !mg.Verbose() && !mg.Debug() {
		// In normal mode, hide DEBUG messages and file/line numbers
		config.DisableCaller = true
		config.Level = zap.NewAtomicLevelAt(zapcore.InfoLevel)
	}

	// Always disable error traces and use color-coded log levels and short timestamps
	config.DisableStacktrace = true
	config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	config.EncoderConfig.EncodeTime = simpleTimeEncoder

	rawLogger, err := config.Build()
	if err != nil {
		log.Fatalf("failed to build logger: %s", err)
	}
	logger = rawLogger.Sugar()
}
