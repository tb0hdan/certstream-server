package log

import (
	"github.com/hashicorp/go-retryablehttp"
	"go.uber.org/zap"
)

type Logger struct {
	logger *zap.Logger
}

func (l *Logger) Error(msg string, keysAndValues ...interface{}) {
	l.logger.Error(msg, zap.Any("keysAndValues", keysAndValues))
}

func (l *Logger) Info(msg string, keysAndValues ...interface{}) {
	l.logger.Info(msg, zap.Any("keysAndValues", keysAndValues))
}

func (l *Logger) Debug(msg string, keysAndValues ...interface{}) {
	l.logger.Debug(msg, zap.Any("keysAndValues", keysAndValues))
}

func (l *Logger) Warn(msg string, keysAndValues ...interface{}) {
	l.logger.Warn(msg, zap.Any("keysAndValues", keysAndValues))
}

func NewLogger(logger *zap.Logger) retryablehttp.LeveledLogger {
	return &Logger{logger: logger}
}
