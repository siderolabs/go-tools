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

	"github.com/siderolabs/go-tools/pkg/signer"
)

var signCmd = &cobra.Command{
	Use:   "sign <image1> <image2> [...]",
	Short: "Sign multiple container images using Cosign under the hood.",
	Long: `Usage: image-signer sign <image1> <image2> [...]
	Sign multiple container images using Cosign under the hood. If the image is already signed,
	it will be skipped.

	This is a wrapper around the Cosign API's so that we only need to authenticate once
	to sign multiple images, subsequent signing operations will reuse the same authentication
	context.

	This explicitly follows "device" authentication flow, so this can be run in a headless environment too.`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return signImages(args)
	},
}

var signOptions struct {
	CertificateIdentityRegexp string
	CertificateOIDCIssuer     string
	OIDCProvider              string
	Timeout                   time.Duration

	DeviceFlow bool
}

func signImages(images []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	for _, image := range images {
		fmt.Printf("Processing image: %s\n", image)

		signatureInfo, err := signer.VerifySignature(ctx, image, []cosign.Identity{
			{
				Issuer:        signOptions.CertificateOIDCIssuer,
				SubjectRegExp: signOptions.CertificateIdentityRegexp,
			},
		})
		if err != nil {
			return err
		}

		if signatureInfo.LegacySignature && signatureInfo.BundleSignature {
			fmt.Println("Image is already signed with both legacy and bundled signatures, skipping signing.")

			continue
		}

		if err := signer.SignImage(image, signatureInfo.LegacySignature, signatureInfo.BundleSignature, signOptions.OIDCProvider, signOptions.DeviceFlow, signOptions.Timeout); err != nil {
			return fmt.Errorf("failed to sign image %s: %w", image, err)
		}

		fmt.Printf("Successfully signed image: %s\n", image)
	}

	return nil
}

func init() {
	signCmd.Flags().BoolVarP(&signOptions.DeviceFlow, "device-flow", "d", false, "Use device flow for authentication")
	signCmd.Flags().StringVarP(&signOptions.CertificateIdentityRegexp, "certificate-identity-regexp", "i", "@siderolabs\\.com$", "The identity regular expression to use for certificate verification")
	signCmd.Flags().StringVarP(&signOptions.CertificateOIDCIssuer, "certificate-oidc-issuer", "o", "https://accounts.google.com", "The OIDC issuer URL to use for certificate verification")
	signCmd.Flags().StringVarP(&signOptions.OIDCProvider, "oidc-provider", "p", "google", "The OIDC provider to use for authentication, supported values are: google, github, microsoft, Set to empty string to use the default HTML page for selection") //nolint:lll
	signCmd.Flags().DurationVarP(&signOptions.Timeout, "timeout", "t", 5*time.Minute, "The timeout duration for signing operations")

	rootCmd.AddCommand(signCmd)
}
