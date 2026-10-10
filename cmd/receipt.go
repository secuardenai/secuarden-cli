package cmd

import (
	"fmt"

	"github.com/secuardenai/secuarden-cli/internal/changereceipt"
	"github.com/secuardenai/secuarden-cli/internal/config"
	"github.com/spf13/cobra"
)

func init() {
	receipt := &cobra.Command{Use: "receipt", Short: "Signed change-receipt v1 workflow"}
	register := &cobra.Command{
		Use: "register-key", Short: "Generate and register an in-memory receipt signing key",
		Long: "Generate an ephemeral Ed25519 key and register its public key with SaaS. Requires SaaS setup for the local Git repository selected by --repo (default current directory); user-wide credentials are not used. Run secuarden init --api-key ... in that repository first. This initial integration check does not create a receipt; the private key is discarded when the command exits.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			path, _ := cmd.Flags().GetString("repo")
			cfg, err := config.LoadForRepository(path)
			if err != nil {
				return err
			}
			name, _ := cmd.Flags().GetString("repository")
			provider, registration, err := changereceipt.PrepareSigningKey(cmd.Context(), cfg, name, cmd.ErrOrStderr(), nil)
			if err != nil {
				return err
			}
			defer provider.Close()
			fmt.Fprintf(cmd.OutOrStdout(), "Registered signing key %s for %s. No receipt created; ephemeral private key discarded on exit.\n", registration.KeyID, registration.Repository.FullName)
			return nil
		},
	}
	register.Flags().String("repository", "", "authorized GitHub repository (owner/name)")
	register.Flags().String("repo", ".", "local Git repository whose required SaaS configuration is used")
	_ = register.MarkFlagRequired("repository")
	receipt.AddCommand(register)
	addReceiptWorkflow(receipt)
	ledgerCmd.AddCommand(receipt)
}
