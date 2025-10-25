// path: src/config/config.go
package config

import (
	_ "embed"

	"github.com/daniellavrushin/b4sni/log"
	"github.com/spf13/cobra"
)

type Config struct {
	Interface string  `json:"interface" bson:"interface"`
	Logging   Logging `json:"logging" bson:"logging"`
}
type Logging struct {
	Level      log.Level `json:"level" bson:"level"`
	Instaflush bool      `json:"instaflush" bson:"instaflush"`
	Syslog     bool      `json:"syslog" bson:"syslog"`
}

var DefaultConfig = Config{
	Interface: "all",
}

func (c *Config) BindFlags(cmd *cobra.Command) {

	// Network configuration
	cmd.Flags().StringVar(&c.Interface, "interface", c.Interface, "Network interface to bind to (e.g., eth0, all)")

	// Logging configuration
	cmd.Flags().BoolVar(&c.Logging.Instaflush, "log-instafflush", c.Logging.Instaflush, "Enable instant flushing of log messages")
	cmd.Flags().BoolVar(&c.Logging.Syslog, "log-syslog", c.Logging.Syslog, "Enable logging to syslog")

}

func (cfg *Config) ApplyLogLevel(level string) {
	switch level {
	case "debug":
		cfg.Logging.Level = log.LevelDebug
	case "trace":
		cfg.Logging.Level = log.LevelTrace
	case "info":
		cfg.Logging.Level = log.LevelInfo
	case "error":
		cfg.Logging.Level = log.LevelError
	case "silent":
		cfg.Logging.Level = -1
	default:
		cfg.Logging.Level = log.LevelInfo
	}
}
