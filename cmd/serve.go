package cmd

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/secuardenai/secuarden-cli/internal/storage"
	"github.com/secuardenai/secuarden-cli/internal/webui"
	"github.com/spf13/cobra"
)

var (
	serveAddress  string
	serveDatabase string
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Browse locally captured evidence",
	Long:  "Start a read-only local web server for browsing captured sessions and events.",
	Args:  cobra.NoArgs,
	RunE:  runServe,
}

func init() {
	serveCmd.Flags().StringVar(&serveAddress, "address", "127.0.0.1:8743", "local address to listen on")
	serveCmd.Flags().StringVar(&serveDatabase, "database", "", "path to a Secuarden database (default ~/.secuarden/secuarden.db)")
}

func runServe(cmd *cobra.Command, _ []string) error {
	if err := validateLoopbackAddress(serveAddress); err != nil {
		return err
	}
	dbPath := serveDatabase
	if dbPath == "" {
		var err error
		dbPath, err = storage.DefaultDBPath()
		if err != nil {
			return err
		}
	}
	db, err := storage.Open(dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	listener, err := net.Listen("tcp", serveAddress)
	if err != nil {
		return fmt.Errorf("start local evidence server: %w", err)
	}
	defer listener.Close()

	server := &http.Server{
		Handler:           webui.New(db, Version).Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	go func() {
		<-cmd.Context().Done()
		_ = server.Close()
	}()

	fmt.Fprintf(cmd.OutOrStdout(), "Secuarden local evidence is available at http://%s\n", listener.Addr().String())
	fmt.Fprintln(cmd.OutOrStdout(), "Read-only · local device only · press Ctrl+C to stop")
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func validateLoopbackAddress(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid --address %q: %w", address, err)
	}
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("--address must use a loopback host such as 127.0.0.1 or ::1")
	}
	return nil
}
