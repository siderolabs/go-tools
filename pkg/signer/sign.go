// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package signer

import (
	"fmt"
	"time"

	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/v3/pkg/cosign"
)

func SignImage(image string, legacySigned, bundleSigned bool, provider string, deviceFlow bool, timeout time.Duration) error {
	trustedRoot, err := cosign.TrustedRoot()
	if err != nil {
		return fmt.Errorf("error getting trusted roots: %w", err)
	}

	token, err := getToken(provider, deviceFlow)()
	if err != nil {
		return fmt.Errorf("error getting OIDC token: %w", err)
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
	}

	rootOptions := &options.RootOptions{
		Timeout: timeout,
	}

	if !legacySigned {
		fmt.Printf("Signing legacy signature for image: %s\n", image)

		if err := sign.SignCmd(rootOptions, keyOptions, signingOptions, []string{image}); err != nil {
			return fmt.Errorf("error signing legacy signature for image %s: %w", image, err)
		}
	}

	if !bundleSigned {
		keyOptions.NewBundleFormat = true
		signingOptions.NewBundleFormat = true
		signingOptions.UseSigningConfig = true

		fmt.Printf("Signing bundled signature for image: %s\n", image)

		if err := sign.SignCmd(rootOptions, keyOptions, signingOptions, []string{image}); err != nil {
			return fmt.Errorf("error signing bundled signature for image %s: %w", image, err)
		}
	}

	return nil
}
