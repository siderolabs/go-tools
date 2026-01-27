// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package signer

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/v3/pkg/cosign"
)

// VerifySignature verifies the signature of the given container image.
func VerifySignature(ctx context.Context, image string, identities []cosign.Identity) (bool, error) {
	ref, err := name.ParseReference(image)
	if err != nil {
		return false, fmt.Errorf("error parsing image reference for %s: %w", image, err)
	}

	trustedRoot, err := cosign.TrustedRoot()
	if err != nil {
		return false, fmt.Errorf("error getting trusted roots: %w", err)
	}

	_, bundleVerified, err := cosign.VerifyImageAttestations(ctx, ref, &cosign.CheckOpts{
		Identities:      identities,
		NewBundleFormat: true,
		TrustedMaterial: trustedRoot,
	})
	if err == nil {
		return bundleVerified, nil
	}

	var noAttestationFoundErr *cosign.ErrNoMatchingAttestations

	return !errors.As(err, &noAttestationFoundErr), nil
}
