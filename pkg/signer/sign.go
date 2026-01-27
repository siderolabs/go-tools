// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package signer

import (
	"context"
	"fmt"
	"time"

	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/v3/pkg/cosign"
)

func SignImage(ctx context.Context, image string, provider string, timeout time.Duration, token string) error {
	trustedRoot, err := cosign.TrustedRoot()
	if err != nil {
		return fmt.Errorf("error getting trusted roots: %w", err)
	}

	keyOptions := options.KeyOpts{
		FulcioURL:        options.DefaultFulcioURL,
		RekorURL:         options.DefaultRekorURL,
		OIDCIssuer:       options.DefaultOIDCIssuerURL,
		OIDCClientID:     SigstoreOIDCClientID,
		SkipConfirmation: true,
		TrustedMaterial:  trustedRoot,
		IDToken:          token,
		FulcioAuthFlow:   "token",
		NewBundleFormat:  true,
	}

	signingOptions := options.SignOptions{
		Upload:     true,
		TlogUpload: true,
		Rekor: options.RekorOptions{
			URL: options.DefaultRekorURL,
		},
		Fulcio: options.FulcioOptions{
			URL: options.DefaultFulcioURL,
		},
		OIDC: options.OIDCOptions{
			Issuer:   options.DefaultOIDCIssuerURL,
			ClientID: SigstoreOIDCClientID,
		},
		NewBundleFormat:  true,
		UseSigningConfig: true,
	}

	rootOptions := &options.RootOptions{
		Timeout: timeout,
	}

	fmt.Printf("Signing bundled signature for image: %s\n", image)

	if err := sign.SignCmd(ctx, rootOptions, keyOptions, signingOptions, []string{image}); err != nil {
		return fmt.Errorf("error signing bundled signature for image %s: %w", image, err)
	}

	return nil
}
