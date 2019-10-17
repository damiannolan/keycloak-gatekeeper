package gatekeeper

import (
	"io/ioutil"
	httplog "log"
	"os"
	"time"

	"github.com/sirupsen/logrus"
)

// TenantHook adds the tenantID to each log entry
type TenantHook struct {
	tenantID string
}

// Levels returns a logrus.Level slice containing all levels the hook is fired on
func (h *TenantHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

// Fire is the trigger in which Hook logic lives and is executed upon log entry
func (h *TenantHook) Fire(e *logrus.Entry) error {
	e.Data["tenant"] = h.tenantID
	return nil
}

// createLogger is responsible for creating the service logger
func createLogger(config *Config) *logrus.Logger {
	httplog.SetOutput(ioutil.Discard) // disable the http logger

	logger := &logrus.Logger{
		Out:       os.Stdout,
		Formatter: newTextFormatter(),
		Hooks:     make(logrus.LevelHooks),
		Level:     logrus.DebugLevel,
	}

	logger.AddHook(&TenantHook{tenantID: config.TenantID})

	if config.DisableAllLogging {
		logger.SetOutput(ioutil.Discard)
	}

	if config.Verbose {
		logger.Level = logrus.TraceLevel
	}

	return logger
}

func newJSONFormatter() *logrus.JSONFormatter {
	return &logrus.JSONFormatter{
		TimestampFormat: time.RFC3339Nano,
	}
}

func newTextFormatter() *logrus.TextFormatter {
	return &logrus.TextFormatter{
		DisableColors:   true,
		FullTimestamp:   true,
		TimestampFormat: time.RFC3339Nano,
	}
}
