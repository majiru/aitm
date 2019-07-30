# Auth in the Middle
This package provides a simple, mostly secure cookie based auth middleware for http.Server.

## Usage
aitm.Server is meant to wrap around an existing http.Server and broker requests, only
passing them to the 'child' http.Handler when the user has authenticated.

At the moment, the only supported way of storing the user databse is in a json file,
the json file is expected to be a marshaled slice of the User struct defined in aitm.go.

User information can be grabbed in the client http.Handler through the use of the context.Context struct
accessible from http.Request.Context(). Specifically, the Token struct is stored in the request on
successful auth with a key of `TokenContextKey{}`.

## Installation
`go get github.com/majiru/aitm`

## Example
```go
import (
	"fmt"
	"log"
	"net/http"

	"github.com/majiru/aitm"
)

func main() {
	srv := aitm.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t := r.Context().Value(TokenContextKey{}).(*aitm.Token)
		fmt.Fprintf(w, "Welcome user %s\n", t.Username)
	}))
	f, _ := os.Open("path/to/db.json")
	srv.LoadUsers(f)
	f.Close()
	srv.Addr = ":8080"
	log.Fatal(srv.ListenAndServe())
}
```

## Implementation
The passwords are hashed and salted using bcrypt. The session cookies are identified based on the
github.com/google/uuid package. Each cookie lives for a maximum of 1 day by default.