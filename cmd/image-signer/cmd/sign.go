// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/spf13/cobra"

	"github.com/siderolabs/go-tools/internal/pkg/auth"
	"github.com/siderolabs/go-tools/pkg/signer"
)

var signCmd = &cobra.Command{
	Use:   "sign <image1> <image2> [...]",
	Short: "Sign multiple container images using Cosign under the hood.",
	Long: `Usage: image-signer sign <image1> <image2> [...]
	Sign multiple container images using Cosign under the hood. If the image is already signed,
	it will be skipped.`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return signImages(args)
	},
}

var signOptions struct {
	CertificateIdentity   string
	CertificateOIDCIssuer string
	OIDCProvider          string

	ServiceAccount string
	Timeout        time.Duration

	DeviceFlow bool
	DryRun     bool
}

func signImages(images []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	// Get OAuth token once for all images
	token, err := auth.GetOAUTHToken(ctx, signOptions.ServiceAccount)
	if err != nil {
		return fmt.Errorf("failed to get OAuth token: %w", err)
	}

	for _, image := range images {
		fmt.Printf("Processing image: %s\n", image)

		verified, err := signer.VerifySignature(ctx, image, []cosign.Identity{
			{
				Issuer:  signOptions.CertificateOIDCIssuer,
				Subject: signOptions.CertificateIdentity,
			},
		})
		if err != nil {
			return err
		}

		if verified {
			fmt.Println("Image is already signed, skipping signing.")

			continue
		}

		if signOptions.DryRun {
			fmt.Println("Dry run enabled, skipping signing.")

			continue
		}

		if err := signer.SignImage(ctx, image, signOptions.OIDCProvider, signOptions.Timeout, token); err != nil {
			return fmt.Errorf("failed to sign image %s: %w", image, err)
		}

		fmt.Printf("Successfully signed image: %s\n", image)
	}

	return nil
}

func init() {
	signCmd.Flags().BoolVarP(&signOptions.DryRun, "dry-run", "", false, "Perform a dry run without actually signing the images")
	signCmd.Flags().StringVarP(&signOptions.CertificateIdentity, "certificate-identity", "i", "releasemgr-svc@talos-production.iam.gserviceaccount.com", "The identity to use for certificate verification") //nolint:lll
	signCmd.Flags().StringVarP(&signOptions.CertificateOIDCIssuer, "certificate-oidc-issuer", "o", "https://accounts.google.com", "The OIDC issuer URL to use for certificate verification")
	signCmd.Flags().DurationVarP(&signOptions.Timeout, "timeout", "t", 5*time.Minute, "The timeout duration for signing operations")
	signCmd.Flags().StringVarP(&signOptions.ServiceAccount, "service-account", "s", "releasemgr-svc@talos-production.iam.gserviceaccount.com", "The Google Cloud service account to use for authentication") //nolint:lll

	rootCmd.AddCommand(signCmd)
}
