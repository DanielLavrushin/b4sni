// path: src/config/config.go
package config

import (
	"fmt"

	"github.com/spf13/cobra"
)

type Config struct {
	QueueStartNum  int
	Mark           uint
	ConnBytesLimit int
	Interface      string
	Logging        Logging
	SNIDomains     []string
	Threads        int
	UseGSO         bool
	UseConntrack   bool
	SkipIpTables   bool
	Mangle         *MangleConfig
	GeodataPath    string
	Sites          []string
}

type MangleConfig struct {
	Enabled       bool
	TCPStrategies []interface{}
	UDPStrategies []interface{}
}

type Logging struct {
	Level      int
	Instaflush bool
	Syslog     bool
}

const (
	InfoLevel = iota
	DebugLevel
	TraceLevel
)

var DefaultConfig = Config{
	QueueStartNum:  537,
	Mark:           1 << 15,
	Threads:        4,
	ConnBytesLimit: 19,
	UseConntrack:   false,
	UseGSO:         false,
	SkipIpTables:   false,
	Interface:      "*",
	GeodataPath:    "",
	Sites:          []string{},
	Logging: Logging{
		Level:      InfoLevel,
		Instaflush: true,
		Syslog:     false,
	},
	Mangle: &MangleConfig{
		Enabled:       false,
		TCPStrategies: nil,
		UDPStrategies: nil,
	},
}

func (c *Config) BindFlags(cmd *cobra.Command) {
	// Network configuration
	cmd.Flags().IntVar(&c.QueueStartNum, "queue-num", c.QueueStartNum,
		"Netfilter queue number")
	cmd.Flags().IntVar(&c.Threads, "threads", c.Threads,
		"Number of worker threads")
	cmd.Flags().UintVar(&c.Mark, "mark", c.Mark,
		"Packet mark value")
	cmd.Flags().IntVar(&c.ConnBytesLimit, "connbytes-limit", c.ConnBytesLimit,
		"Connection bytes limit")
	cmd.Flags().StringVar(&c.Interface, "iface", c.Interface,
		"Network interface (* for all)")
	cmd.Flags().StringSliceVar(&c.SNIDomains, "sni-domains", c.SNIDomains,
		"List of SNI domains to match")

	// Geodata and site filtering
	cmd.Flags().StringVar(&c.GeodataPath, "geodata", c.GeodataPath,
		"Path to geodata file (e.g., geosite.dat)")
	cmd.Flags().StringSliceVar(&c.Sites, "site", c.Sites,
		"Sites to process (e.g., youtube,facebook,amazon)")

	// Feature flags
	cmd.Flags().BoolVar(&c.UseGSO, "gso", c.UseGSO,
		"Enable Generic Segmentation Offload")
	cmd.Flags().BoolVar(&c.UseConntrack, "conntrack", c.UseConntrack,
		"Enable connection tracking")
	cmd.Flags().BoolVar(&c.SkipIpTables, "skip-iptables", c.SkipIpTables,
		"Skip iptables rules setup")

	// Logging configuration
	cmd.Flags().BoolVarP(&c.Logging.Instaflush, "instaflush", "i", c.Logging.Instaflush,
		"Flush logs immediately")
	cmd.Flags().BoolVar(&c.Logging.Syslog, "syslog", c.Logging.Syslog,
		"Enable syslog output")
}

func (c *Config) ApplyVerbosityFlags(verbose, trace bool) {
	if trace {
		c.Logging.Level = TraceLevel
	} else if verbose {
		c.Logging.Level = DebugLevel
	}
}

func (c *Config) Validate() error {
	// If sites are specified, geodata path must be provided
	if len(c.Sites) > 0 && c.GeodataPath == "" {
		return fmt.Errorf("--geodata must be specified when using --site")
	}

	if c.Threads < 1 {
		return fmt.Errorf("threads must be at least 1")
	}

	if c.QueueStartNum < 0 || c.QueueStartNum > 65535 {
		return fmt.Errorf("queue-num must be between 0 and 65535")
	}

	return nil
}

func (c *Config) LogString() string {
	return ""
}
