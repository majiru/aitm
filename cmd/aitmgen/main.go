package main

import(
	"bufio"
	"encoding/json"
	"os"
	"strings"
	"log"

	"github.com/majiru/aitm"
	"golang.org/x/crypto/bcrypt"
)

func main(){
	var users []aitm.User
	scan := bufio.NewScanner(os.Stdin)
	for scan.Scan() {
		parts := strings.Split(scan.Text(), ":")
		if len(parts) < 2 {
			log.Fatal("malformed input")
		}
		crypt, err := bcrypt.GenerateFromPassword([]byte(parts[1]), bcrypt.DefaultCost)
		if err != nil {
			log.Fatal(err)
		}
		users = append(users, aitm.User{
			Username: parts[0],
			Password: string(crypt),
		})
	}
	b, err := json.MarshalIndent(users, "", "\t")
	if err != nil {
		log.Fatal(err)
	}
	os.Stdout.Write(b)
}
