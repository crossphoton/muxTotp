package muxTotp

import (
	"bytes"
	"encoding/json"
	"image/jpeg"
	"log"
	"net/http"
	"net/url"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

type VerifyRedirect struct {
	Secret   string
	Continue string
	Error    string
	Pre      string
}

func (s *VerifyRedirect) redirectURL() string {
	Pre := url.QueryEscape(s.Pre)
	Continue := url.QueryEscape(s.Continue)
	Secret := url.QueryEscape(s.Secret)
	Error := url.QueryEscape(s.Error)

	result := Pre + "/verify-with-secret?continue=" + Continue + "&secret=" + Secret

	if Error != "" {
		result += "&error=" + Error
	}

	return result
}

type newURLReturnType struct {
	URL     string `json:"url"`
	Account string `json:"account"`
	Secret  string `json:"secret"`
}

var TOTPOpts totp.GenerateOpts

func verifyTOTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("secret") == "" || r.URL.Query().Get("otp") == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("parameters insufficient. add ?secret=________&otp=________"))
		return
	}

	secret := r.URL.Query().Get("secret")
	passcode := r.URL.Query().Get("otp")

	result := totp.Validate(passcode, secret)

	if result {
		if r.URL.Query().Get("continue") != "" {
			http.Redirect(w, r, r.URL.Query().Get("continue"), http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.URL.Query().Get("error") != "" {
		http.Redirect(w, r, r.URL.Query().Get("error"), http.StatusUnauthorized)
		return
	}
	w.WriteHeader(http.StatusUnauthorized)
}

func getQRCode(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("url") == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("account name not given. add ?url=________"))
		return
	}

	key, _ := otp.NewKeyFromURL(r.URL.Query().Get("url"))
	image, _ := key.Image(200, 200)

	buffer := new(bytes.Buffer)
	if err := jpeg.Encode(buffer, image, nil); err != nil {
		log.Println("unable to encode image.")
	}

	w.Header().Set("Content-Type", "image/jpeg")
	w.Header().Set("Content-Length", strconv.Itoa(len(buffer.Bytes())))

	if _, err := w.Write(buffer.Bytes()); err != nil {
		log.Println("unable to write image.")
	}
}

func newSecret(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("account") == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("account name not given. add ?account=________"))
		return
	}
	TOTPOpts.AccountName = r.URL.Query().Get("account")

	a, err := totp.Generate(TOTPOpts)
	if err != nil {
		log.Fatalln("error generating secret", err)
	}

	a.Image(200, 200)

	resultJson, err := json.Marshal(newURLReturnType{
		URL:     a.URL(),
		Account: a.AccountName(),
		Secret:  a.Secret(),
	})

	if err != nil {
		log.Fatal("error in json encoding", err)
	}

	w.Write(resultJson)
}

func Router(opts totp.GenerateOpts, r *mux.Router) {
	TOTPOpts = opts
	r.HandleFunc("/new-url", newSecret)
	r.HandleFunc("/verify-with-secret", verifyTOTP)
	r.HandleFunc("/get-image", getQRCode)
}
