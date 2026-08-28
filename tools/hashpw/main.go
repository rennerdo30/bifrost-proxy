// Command hashpw generates a bcrypt password hash for the native auth
// provider's password_hash field.
//
// Three documentation pages instruct operators to run
// `go run github.com/rennerdo30/bifrost-proxy/tools/hashpw password` — and
// this program did not exist, leaving no shipped way to mint a hash.
//
// The password is read from stdin when no argument is given, which keeps it
// out of shell history and process listings; passing it as an argument stays
// supported because that is the documented form.
package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/rennerdo30/bifrost-proxy/internal/auth"
)

func main() {
	var password string
	switch len(os.Args) {
	case 1:
		fmt.Fprint(os.Stderr, "Password: ")
		reader := bufio.NewReader(os.Stdin)
		line, err := reader.ReadString('\n')
		if err != nil && line == "" {
			fmt.Fprintf(os.Stderr, "read password: %v\n", err)
			os.Exit(1)
		}
		password = strings.TrimRight(line, "\r\n")
	case 2:
		password = os.Args[1]
	default:
		fmt.Fprintln(os.Stderr, "usage: hashpw [password]  (omit the argument to read from stdin)")
		os.Exit(2)
	}

	if password == "" {
		fmt.Fprintln(os.Stderr, "hashpw: empty password")
		os.Exit(1)
	}

	hash, err := auth.HashPassword(password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "hash password: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(hash)
}
