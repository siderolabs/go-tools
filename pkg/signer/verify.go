// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package signer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/cosign/v3/pkg/types"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore/pkg/signature/payload"
)

type signatureStatus struct {
	LegacySignature bool
	BundleSignature bool
}

// VerifySignature verifies the signature of the given container image
// and returns whether the legacy and bundled signatures are present.
// In this case we verify that both Cosign legacy and bundled type signatures are present, so older clients can also verify them.
// legacy type => `cosign container image signature`
// bundled type => `https://sigstore.dev/cosign/sign/v1`
func VerifySignature(ctx context.Context, image string, identities []cosign.Identity) (*signatureStatus, error) {
	ref, err := name.ParseReference(image)
	if err != nil {
		return nil, fmt.Errorf("error parsing image reference for %s: %w", image, err)
	}

	trustedRoot, err := cosign.TrustedRoot()
	if err != nil {
		return nil, fmt.Errorf("error getting trusted roots: %w", err)
	}

	legacyStatus, err := verifyLegacySignature(ctx, ref, trustedRoot, identities)
	if err != nil {
		return nil, fmt.Errorf("error verifying legacy signature: %w", err)
	}

	bundledStatus, err := verifyBundledSignature(ctx, ref, trustedRoot, identities)
	if err != nil {
		return nil, fmt.Errorf("error verifying bundled signature: %w", err)
	}

	return &signatureStatus{
		LegacySignature: legacyStatus,
		BundleSignature: bundledStatus,
	}, nil
}

func verifyLegacySignature(ctx context.Context, ref name.Reference, trustedRoot root.TrustedMaterial, identities []cosign.Identity) (bool, error) {
	signatures, bundleVerified, verifyErr := cosign.VerifyImageSignatures(ctx, ref, &cosign.CheckOpts{
		Identities:      identities,
		TrustedMaterial: trustedRoot,
	})
	if verifyErr == nil {
		if !bundleVerified {
			return false, fmt.Errorf("legacy signatures found but verification failed")
		}

		// loop over all signatures and make sure all are of legacy type
		for _, sig := range signatures {
			signaturePayload, err := sig.Payload()
			if err != nil {
				return false, fmt.Errorf("error getting signature payload: %w", err)
			}

			var info payload.SimpleContainerImage

			if err := json.Unmarshal(signaturePayload, &info); err != nil {
				return false, fmt.Errorf("error unmarshaling signature payload: %w", err)
			}

			if info.Critical.Type != payload.CosignSignatureType {
				return false, fmt.Errorf("legacy signature found but with unexpected type: %s", info.Critical.Type)
			}
		}

		return true, nil
	}

	if validateNoSignatureFound(verifyErr) {
		return false, nil
	}

	return false, verifyErr
}

func verifyBundledSignature(ctx context.Context, ref name.Reference, trustedRoot root.TrustedMaterial, identities []cosign.Identity) (bool, error) {
	signatures, bundleVerified, verifyErr := cosign.VerifyImageAttestations(ctx, ref, &cosign.CheckOpts{
		Identities: identities,

		NewBundleFormat: true,
		TrustedMaterial: trustedRoot,
	})
	if verifyErr == nil {
		if !bundleVerified {
			return false, fmt.Errorf("bundled signatures found but verification failed")
		}

		// loop over all signatures and make sure all are of bundled type
		for _, sig := range signatures {
			signaturePayload, err := sig.Payload()
			if err != nil {
				return false, fmt.Errorf("error getting signature payload: %w", err)
			}

			var info dsse.Envelope

			if err = json.Unmarshal(signaturePayload, &info); err != nil {
				return false, fmt.Errorf("error unmarshaling signature payload: %w", err)
			}

			payloadDecoded, err := info.DecodeB64Payload()
			if err != nil {
				return false, fmt.Errorf("error decoding signature payload: %w", err)
			}

			var statement in_toto.Statement

			if err = json.Unmarshal(payloadDecoded, &statement); err != nil {
				return false, fmt.Errorf("error unmarshaling signature statement: %w", err)
			}

			if statement.PredicateType != types.CosignSignPredicateType {
				return false, fmt.Errorf("bundled signature found but with unexpected type: %s", statement.PredicateType)
			}
		}

		return true, nil
	}

	if validateNoMatchingAttestations(verifyErr) {
		return false, nil
	}

	return false, verifyErr
}

func validateNoSignatureFound(err error) bool {
	var noSignatureFoundErr *cosign.ErrNoSignaturesFound

	return errors.As(err, &noSignatureFoundErr)
}

func validateNoMatchingAttestations(err error) bool {
	var noAttestationFoundErr *cosign.ErrNoMatchingAttestations

	return errors.As(err, &noAttestationFoundErr)
}
