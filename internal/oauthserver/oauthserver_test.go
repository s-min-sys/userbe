package oauthserver

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"testing"
	"time"

	"github.com/go-session/session"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

const (
	authServerURL = "http://localhost:8080"
)

var (
	utConfig = oauth2.Config{
		ClientID:     "0000",
		ClientSecret: "000000",
		Scopes:       []string{"all"},
		RedirectURL:  "http://localhost:9099/oauth2",
		Endpoint: oauth2.Endpoint{
			AuthURL:  authServerURL + "/oauth/authorize",
			TokenURL: authServerURL + "/oauth/token",
		},
	}
)

// nolint
func TestOAuthServer(t *testing.T) {
	session.InitManager(session.SetCookieName("xxx"))
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		u := utConfig.AuthCodeURL("xyz",
			oauth2.SetAuthURLParam("code_challenge", genCodeChallengeS256("s256example")),
			oauth2.SetAuthURLParam("code_challenge_method", "S256"))
		http.Redirect(w, r, u, http.StatusFound)
	})

	fnSetToken := func(w http.ResponseWriter, r *http.Request, token *oauth2.Token) (err error) {
		storage, err := session.Start(r.Context(), w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)

			return
		}

		storage.Set("token", token)

		err = storage.Save()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}

		return
	}

	fnGetToken := func(w http.ResponseWriter, r *http.Request) *oauth2.Token {
		storage, err := session.Start(r.Context(), w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)

			return nil
		}

		tokenI, ok := storage.Get("token")
		if !ok {
			http.Error(w, "no token", http.StatusUnauthorized)

			return nil
		}

		token, ok := tokenI.(*oauth2.Token)
		if !ok {
			http.Redirect(w, r, "/", http.StatusFound)
			return nil
		}

		return token
	}

	http.HandleFunc("/oauth2", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		state := r.Form.Get("state")
		if state != "xyz" {
			http.Error(w, "State invalid", http.StatusBadRequest)
			return
		}
		code := r.Form.Get("code")
		if code == "" {
			http.Error(w, "Code not found", http.StatusBadRequest)
			return
		}
		token, err := utConfig.Exchange(context.Background(), code, oauth2.SetAuthURLParam("code_verifier", "s256example"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		err = fnSetToken(w, r, token)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}

		e := json.NewEncoder(w)
		e.SetIndent("", "  ")
		e.Encode(token)
	})

	http.HandleFunc("/refresh", func(w http.ResponseWriter, r *http.Request) {
		token := fnGetToken(w, r)
		if token == nil {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}

		token.Expiry = time.Now()

		token, err := utConfig.TokenSource(context.Background(), token).Token()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		_ = fnSetToken(w, r, token)

		e := json.NewEncoder(w)
		e.SetIndent("", "  ")
		e.Encode(token)
	})

	http.HandleFunc("/try", func(w http.ResponseWriter, r *http.Request) {
		token := fnGetToken(w, r)
		if token == nil {
			http.Redirect(w, r, "/", http.StatusFound)

			return
		}

		// nolint: noctx
		resp, err := http.Get(fmt.Sprintf("%s/oauth/test?access_token=%s", authServerURL, token.AccessToken))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		defer resp.Body.Close()

		io.Copy(w, resp.Body)
	})

	http.HandleFunc("/pwd", func(w http.ResponseWriter, r *http.Request) {
		token, err := utConfig.PasswordCredentialsToken(context.Background(), "test", "test")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		e := json.NewEncoder(w)
		e.SetIndent("", "  ")
		e.Encode(token)
	})

	http.HandleFunc("/client", func(w http.ResponseWriter, r *http.Request) {
		cfg := clientcredentials.Config{
			ClientID:     utConfig.ClientID,
			ClientSecret: utConfig.ClientSecret,
			TokenURL:     utConfig.Endpoint.TokenURL,
		}

		token, err := cfg.Token(context.Background())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		e := json.NewEncoder(w)
		e.SetIndent("", "  ")
		e.Encode(token)

		_ = fnSetToken(w, r, token)
	})

	log.Fatal(http.ListenAndServe(":9099", nil))
}

func genCodeChallengeS256(s string) string {
	s256 := sha256.Sum256([]byte(s))

	return base64.URLEncoding.EncodeToString(s256[:])
}
