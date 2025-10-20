// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package signer

import (
	"fmt"
	"sync"

	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/sigstore/pkg/oauthflow"
)

func getToken(provider string, deviceFlow bool) func() (string, error) {
	return sync.OnceValues(func() (string, error) {
		var tokenGetter oauthflow.TokenGetter

		switch provider {
		case "":
			tokenGetter = oauthflow.DefaultIDTokenGetter
		case "google":
			tokenGetter = oauthflow.PublicInstanceGoogleIDTokenGetter
		case "github":
			tokenGetter = oauthflow.PublicInstanceGithubIDTokenGetter
		case "microsoft":
			tokenGetter = oauthflow.PublicInstanceMicrosoftIDTokenGetter
		default:
			return "", fmt.Errorf("unsupported provider: %s", provider)
		}

		if deviceFlow {
			tokenGetter = oauthflow.NewDeviceFlowTokenGetterForIssuer(options.DefaultOIDCIssuerURL)
		}

		tok, err := oauthflow.OIDConnect(
			options.DefaultOIDCIssuerURL,
			SigstoreOIDCClientID,
			"",
			"",
			tokenGetter,
		)
		if err != nil {
			return "", err
		}

		return tok.RawString, nil
	})
}
