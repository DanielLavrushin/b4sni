package main

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/daniellavrushin/b4sni/config"
	"github.com/daniellavrushin/b4sni/log"
	"github.com/daniellavrushin/b4sni/sni"
	"github.com/spf13/cobra"
)

var (
	cfg         = config.DefaultConfig
	verboseFlag string
	showVersion bool
	Version     = "dev"
	Commit      = "none"
	Date        = "unknown"
)

var rootCmd = &cobra.Command{
	Use:   "b4",
	Short: "B4 network packet processor",
	Long:  `B4 is a netfilter queue based packet processor for DPI circumvention`,
	RunE:  runB4sni,
}

func init() {
	// Bind all configuration flags
	cfg.BindFlags(rootCmd)

	// Add verbosity flags separately since they need special handling
	rootCmd.Flags().StringVar(&verboseFlag, "verbose", "info", "Set verbosity level (debug, trace, info, silent), default: info")
	rootCmd.Flags().BoolVarP(&showVersion, "version", "v", false, "Show version and exit")
}
func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runB4sni(cmd *cobra.Command, args []string) error {

	if showVersion {
		fmt.Printf("B4SNI version: %s (%s) %s\n", Version, Commit, Date)
		return nil
	}
	cfg.ApplyLogLevel(verboseFlag)
	// Initialize logging first thing
	if err := initLogging(&cfg); err != nil {
		return fmt.Errorf("logging initialization failed: %w", err)
	}

	log.Infof("Starting B4SNI: %s (%s) %s", Version, Commit, Date)
	extractor := &sni.SNIExtractor{
		TcpTracker: sni.NewTCPStreamTracker(),
	}

	if err := extractor.Init(); err != nil {
		log.Errorf("Failed to initialize B4SNI extractor: %v", err)
	}
	defer extractor.Close()

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Stats ticker
	statsTicker := time.NewTicker(30 * time.Second)
	defer statsTicker.Stop()

	go func() {
		for range sigChan {
			log.Infof("Shutting down...")
			extractor.Close()
			os.Exit(0)
		}
	}()

	extractor.Run()

	return nil
}

func initLogging(cfg *config.Config) error {
	// Ensure logging is initialized with stderr output
	w := io.MultiWriter(os.Stderr)
	log.Init(w, log.Level(cfg.Logging.Level), cfg.Logging.Instaflush)

	// Log that initialization happened
	fmt.Fprintf(os.Stderr, "[INIT] Logging initialized at level %d\n", cfg.Logging.Level)

	if cfg.Logging.Syslog {
		if err := log.EnableSyslog("b4sni"); err != nil {
			log.Errorf("Failed to enable syslog: %v", err)
			return err
		}
		log.Infof("Syslog enabled")
	}

	return nil
}
