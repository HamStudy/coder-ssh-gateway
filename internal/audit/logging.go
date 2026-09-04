package audit

import (
	"log/slog"
	"os"
)

func NewLogger(format string, level string) (*slog.Logger, error) {
	var handler slog.Handler
	opts := &slog.HandlerOptions{}

	switch format {
	case "json":
		handler = slog.NewJSONHandler(os.Stdout, opts)
	case "text":
		handler = slog.NewTextHandler(os.Stdout, opts)
	default:
		return nil, ErrInvalidLogFormat
	}

	var logLevel slog.Level
	switch level {
	case "debug":
		logLevel = slog.LevelDebug
	case "info":
		logLevel = slog.LevelInfo
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		return nil, ErrInvalidLogLevel
	}

	opts.Level = logLevel

	logger := slog.New(handler)
	return logger, nil
}

func WithStdFields(logger *slog.Logger, connectionID string, deploymentID string) *slog.Logger {
	if logger == nil {
		return nil
	}

	return logger.With(
		slog.String("connection_id", connectionID),
		slog.String("deployment_id", deploymentID),
	)
}
