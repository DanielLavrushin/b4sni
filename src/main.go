// path: src/main.go
package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/daniellavrushin/b4sni/config"
	"github.com/daniellavrushin/b4sni/iptables"
	"github.com/daniellavrushin/b4sni/log"
	"github.com/daniellavrushin/b4sni/nfq"
	"github.com/spf13/cobra"
)

var (
	cfg         = config.DefaultConfig
	verboseFlag bool
	traceFlag   bool
)

var rootCmd = &cobra.Command{
	Use:   "b4",
	Short: "B4 network packet processor",
	Long:  `B4 is a netfilter queue based packet processor for DPI circumvention`,
	RunE:  runB4,
}

func init() {
	// Bind all configuration flags
	cfg.BindFlags(rootCmd)

	// Add verbosity flags separately since they need special handling
	rootCmd.Flags().BoolVarP(&verboseFlag, "verbose", "v", false, "Enable verbose (debug) logging")
	rootCmd.Flags().BoolVar(&traceFlag, "trace", false, "Enable trace logging")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runB4(cmd *cobra.Command, args []string) error {
	// Debug output to stderr to see if we're even getting here
	fmt.Fprintf(os.Stderr, "[DEBUG] runB4 started\n")

	// Apply verbosity settings
	cfg.ApplyVerbosityFlags(verboseFlag, traceFlag)
	fmt.Fprintf(os.Stderr, "[DEBUG] Verbosity applied, log level: %d\n", cfg.Logging.Level)

	// Initialize logging first thing
	if err := initLogging(&cfg); err != nil {
		return fmt.Errorf("logging initialization failed: %w", err)
	}
	fmt.Fprintf(os.Stderr, "[DEBUG] Logging initialized\n")

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	log.Infof("Starting B4 packet processor")
	fmt.Fprintf(os.Stderr, "[DEBUG] After first log.Infof\n")
	logConfiguration(&cfg)

	// Setup iptables rules
	if !cfg.SkipIpTables {
		log.Infof("Clearing existing iptables rules")
		iptables.ClearRules(&cfg)

		log.Infof("Adding iptables rules")
		if err := iptables.AddRules(&cfg); err != nil {
			return fmt.Errorf("failed to add iptables rules: %w", err)
		}
	} else {
		log.Infof("Skipping iptables setup (--skip-iptables)")
	}

	// Start netfilter queue pool
	log.Infof("Starting netfilter queue pool (queue: %d, threads: %d)", cfg.QueueStartNum, cfg.Threads)
	pool := nfq.NewPool(uint16(cfg.QueueStartNum), cfg.Threads, &cfg)
	if err := pool.Start(); err != nil {
		return fmt.Errorf("netfilter queue start failed: %w", err)
	}
	defer pool.Stop()

	log.Infof("B4 is running. Press Ctrl+C to stop")

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigChan

	log.Infof("Received signal: %v, shutting down gracefully", sig)

	// Cleanup iptables rules
	if !cfg.SkipIpTables {
		log.Infof("Clearing iptables rules")
		if err := iptables.ClearRules(&cfg); err != nil {
			log.Errorf("Failed to clear iptables rules: %v", err)
		}
	}

	log.Infof("B4 stopped successfully")
	return nil
}

func initLogging(cfg *config.Config) error {
	// Ensure logging is initialized with stderr output
	log.Init(os.Stderr, log.Level(cfg.Logging.Level), cfg.Logging.Instaflush)

	// Log that initialization happened
	fmt.Fprintf(os.Stderr, "[INIT] Logging initialized at level %d\n", cfg.Logging.Level)

	if cfg.Logging.Syslog {
		if err := log.EnableSyslog("b4"); err != nil {
			log.Errorf("Failed to enable syslog: %v", err)
			return err
		}
		log.Infof("Syslog enabled")
	}

	return nil
}

func logConfiguration(cfg *config.Config) {
	log.Debugf("Configuration:")
	log.Debugf("  Queue number: %d", cfg.QueueStartNum)
	log.Debugf("  Threads: %d", cfg.Threads)
	log.Debugf("  Mark: %d (0x%x)", cfg.Mark, cfg.Mark)
	log.Debugf("  ConnBytes limit: %d", cfg.ConnBytesLimit)
	log.Debugf("  Interface: %s", cfg.Interface)
	log.Debugf("  GSO: %v", cfg.UseGSO)
	log.Debugf("  Conntrack: %v", cfg.UseConntrack)
	log.Debugf("  Skip iptables: %v", cfg.SkipIpTables)
	if cfg.GeodataPath != "" {
		log.Debugf("  Geodata: %s", cfg.GeodataPath)
	}
	if len(cfg.Sites) > 0 {
		log.Debugf("  Sites: %v", cfg.Sites)
	}
	if len(cfg.SNIDomains) > 0 {
		log.Debugf("  SNI Domains: %v", cfg.SNIDomains)
	}
	log.Debugf("  Logging level: %d", cfg.Logging.Level)
}
