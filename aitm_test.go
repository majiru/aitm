package aitm

import (
	"encoding/json"
	"bytes"
	"io/ioutil"
	"net/url"
	"net/http"
	"net/http/httptest"
	"net/http/cookiejar"
	"testing"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/net/publicsuffix"
)

func initServer() (*Server, *httptest.Server) {
	content := []byte("Hello World\n")
	srv := NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(content)
	}))
	ts := httptest.NewServer(srv.Handler)
	return srv, ts
}

func TestRedirect(t *testing.T) {
	_, ts := initServer()
	defer ts.Close()
	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != signinPage {
		t.Fatal("Did not redirect to signin page properly")
	}
}

func TestSignin(t *testing.T) {
	const username = "chris"
	const password = "danny bliss"

	srv, ts := initServer()
	defer ts.Close()

	v := url.Values{}
	v.Add("username", username)
	v.Add("password", password)

	b, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	b, err = json.Marshal(&[]User{User{username, string(b)}})
	if err != nil {
		t.Fatal(err)
	}
	srv.LoadUsers(bytes.NewReader(b))

	j, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		t.Fatal(err)
	}
	c := http.Client{Jar: j}
	resp, err := c.PostForm(ts.URL + "/signin", v)
	if err != nil {
		t.Fatal(err)
	}

	b, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "Hello World\n" {
		t.Fatal("Did not auth: got " + string(b))
	}
}