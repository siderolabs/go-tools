// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package auth

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"cloud.google.com/go/auth"
	"cloud.google.com/go/auth/oauth2adapt"
	"github.com/pkg/browser"
	iam "google.golang.org/api/iamcredentials/v1"
	"google.golang.org/api/option"
)

func GetOAUTHToken(ctx context.Context, serviceAccount string) (string, error) {
	state := "state-token"
	redirectURL := "http://127.0.0.1:8585"

	// Authorization handler opens the browser and listens locally for the callback
	authHandler := func(authCodeURL string) (code string, stateGot string, err error) {
		codeCh := make(chan string, 1)
		stateCh := make(chan string, 1)
		errCh := make(chan error, 1)

		mux := http.NewServeMux()
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			code = r.URL.Query().Get("code")

			st := r.URL.Query().Get("state")

			if code == "" {
				errCh <- fmt.Errorf("no code in callback")

				_, _ = w.Write([]byte("Error: no authorization code received")) //nolint:errcheck

				return
			}

			codeCh <- code

			stateCh <- st

			_, _ = w.Write([]byte("Authentication successful! You can close this window.")) //nolint:errcheck
		})

		server := &http.Server{Addr: ":8585", Handler: mux}

		go func() {
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				errCh <- err
			}
		}()

		defer server.Shutdown(ctx) //nolint:errcheck

		fmt.Println("Opening browser for authentication...")
		fmt.Printf("If the browser doesn't open automatically, visit:\n%s\n\n", authCodeURL)
		_ = browser.OpenURL(authCodeURL) //nolint:errcheck

		select {
		case code = <-codeCh:
			stateGot = <-stateCh

			return code, stateGot, nil
		case err := <-errCh:
			return "", "", err
		case <-ctx.Done():
			return "", "", ctx.Err()
		case <-time.After(5 * time.Minute):
			return "", "", fmt.Errorf("authentication timeout")
		}
	}

	// Create a 3LO token provider with gcloud's public client credentials
	// See: https://akingscote.co.uk/posts/gcloud-unconfigured-third-party-apps/
	// See: https://welw.it/posts/debugging-google-application-default-credentials-9058d0236ebb/
	tp, err := auth.New3LOTokenProvider(&auth.Options3LO{
		ClientID:     "764086051850-6qr4p6gpi6hn506pt8ejuq83di341hur.apps.googleusercontent.com",
		ClientSecret: "d-FL95Q19q7MQmFpd7hHD0Ty", // Google's public client secret for gcloud
		AuthURL:      "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL:     "https://oauth2.googleapis.com/token",
		AuthStyle:    auth.StyleInParams,
		RedirectURL:  redirectURL,
		Scopes:       []string{"https://www.googleapis.com/auth/cloud-platform"},
		AuthHandlerOpts: &auth.AuthorizationHandlerOptions{
			Handler: authHandler,
			State:   state,
		},
	})
	if err != nil {
		return "", fmt.Errorf("failed to create 3LO token provider: %w", err)
	}

	fmt.Println("\nAuthentication successful!")

	// Convert to oauth2.TokenSource for use with Google APIs
	ts := oauth2adapt.TokenSourceFromTokenProvider(tp)

	iamService, err := iam.NewService(ctx, option.WithTokenSource(ts))
	if err != nil {
		return "", fmt.Errorf("failed to create IAM service: %w", err)
	}

	// Generate ID token for the specified service account with sigstore audience
	serviceAccountResource := fmt.Sprintf("projects/-/serviceAccounts/%s", serviceAccount)

	req := &iam.GenerateIdTokenRequest{
		Audience:     "sigstore",
		IncludeEmail: true,
	}

	resp, err := iamService.Projects.ServiceAccounts.GenerateIdToken(serviceAccountResource, req).Context(ctx).Do()
	if err != nil {
		return "", fmt.Errorf("failed to generate ID token for service account %s: %w", serviceAccount, err)
	}

	return resp.Token, nil
}
