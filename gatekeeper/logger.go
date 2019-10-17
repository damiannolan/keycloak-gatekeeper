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
	TenantID string
}

// Levels returns all levels the hook is activate on
func (h *TenantHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

// Fire is trigger on log execution
func (h *TenantHook) Fire(e *logrus.Entry) error {
	e.Data["tenantID"] = h.TenantID
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

	// Add the TenantID as a field on Config
	logger.AddHook(&TenantHook{TenantID: "myTenantID"})

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
