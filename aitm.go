package aitm

import (
	"context"
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type Token struct {
	time.Time
	IP       string
	Username string
}

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Server struct {
	*sync.RWMutex
	*http.Server
	child      http.Handler
	tokenCache map[uuid.UUID]Token
	userDB     map[string][]byte
}

func NewServer(h http.Handler) *Server {
	return WrapServer(&http.Server{Handler: h})
}

func WrapServer(s *http.Server) *Server {
	srv := &Server{
		&sync.RWMutex{},
		s,
		s.Handler,
		make(map[uuid.UUID]Token),
		make(map[string][]byte),
	}
	srv.Handler = srv.NewMux()
	return srv
}

func (s *Server) NewMux() *http.ServeMux {
	mux := &http.ServeMux{}
	mux.HandleFunc("/signin", s.handleSignin)
	mux.HandleFunc("/", s.handleOther)
	return mux
}

func (s *Server) LoadUsers(f io.Reader) error {
	var users []User
	b, err := ioutil.ReadAll(f)
	if err != nil {
		return err
	}
	if err = json.Unmarshal(b, &users); err != nil {
		return err
	}
	s.Lock()
	for _, u := range users {
		s.userDB[u.Username] = []byte(u.Password)
	}
	s.Unlock()
	return nil
}

type TokenContextKey struct{}

func (s *Server) handleOther(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("auth_token")
	if err != nil {
		http.Redirect(w, r, "/signin", 303)
		return
	}
	id, err := uuid.Parse(c.Value)
	if err != nil {
		log.Println(err)
		http.Redirect(w, r, "/signin", 303)
		return
	}
	s.RLock()
	t, ok := s.tokenCache[id]
	s.RUnlock()
	if !ok || time.Now().After(t.Add(24*time.Hour)) {
		http.Redirect(w, r, "/signin", 303)
		return
	}
	r = r.WithContext(context.WithValue(r.Context(), TokenContextKey{}, &t))
	s.child.ServeHTTP(w, r)
}

func (s *Server) handleSignin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		w.Write([]byte(signinPage))
	case http.MethodPost:
		u := r.FormValue("username")
		p := r.FormValue("password")
		if u == "" || p == "" {
			http.Redirect(w, r, "/signin", 303)
			return
		}
		s.RLock()
		c, ok := s.userDB[u]
		s.RUnlock()
		if ok {
			if bcrypt.CompareHashAndPassword(c, []byte(p)) == nil {
				id := uuid.New()
				t := time.Now()
				s.Lock()
				s.tokenCache[id] = Token{t, r.RemoteAddr, u}
				s.Unlock()
				c := &http.Cookie{
					Name:     "auth_token",
					Value:    id.String(),
					Expires:  t.Add(24 * time.Hour),
					HttpOnly: true,
				}
				http.SetCookie(w, c)
				http.Redirect(w, r, "/", 303)
				return
			}
		}
		http.Redirect(w, r, "/signin", 303)
	}
}

const signinPage = `
<!doctype html>
<html lang="en">
	<head>
		<title>Auth in the Middle</title>
	</head>
	<body>
		<form action="/signin" method="post">
			<input id="username" name="username">
			<input id="password" type="password" name="password">
			<button type="submit">Login</button>
		</form>
	</body>
</html>
`
