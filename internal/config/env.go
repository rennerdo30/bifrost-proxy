package config

import (
	"fmt"
	"os"
	"strings"
)

// Environment-variable expansion in configuration files.
//
// Bifrost deliberately uses a narrower syntax than os.ExpandEnv. os.ExpandEnv
// expands bare $NAME sequences, which silently truncates any literal value
// containing a dollar sign (the password "p@ss$word123" became "p@ss"), and it
// has no escape syntax, so YAML quoting could not protect such a value. The
// rules below are the whole grammar:
//
//	${NAME}          value of NAME; empty string plus a warning when unset
//	${NAME:-value}   value of NAME when set and non-empty, otherwise the literal
//	                 fallback (shell ":-" semantics; the fallback is taken
//	                 literally and is not itself expanded)
//	$$               a literal dollar sign
//
// Every other dollar sign is literal, so bcrypt hashes, passwords and API keys
// survive unchanged. Expansion is a single pass over the raw file, so a value
// substituted from the environment is never itself re-expanded.
const (
	// envDollar introduces an escape sequence or a variable reference.
	envDollar = '$'
	// envRefOpen follows envDollar to open a variable reference.
	envRefOpen = '{'
	// envRefClose terminates a variable reference.
	envRefClose = '}'
	// envDefaultSeparator separates the variable name from its fallback value
	// inside a reference: ${NAME:-fallback}.
	envDefaultSeparator = ":-"
	// envNewline is used to track line numbers for diagnostics.
	envNewline = '\n'
	// envEscapeSequence is what a config file must contain to yield a literal
	// dollar sign in front of a "{" or another "$".
	envEscapeSequence = "$$"
)

// EnvWarningKind classifies a non-fatal anomaly found while expanding
// environment-variable references.
type EnvWarningKind string

const (
	// WarnUndefinedVariable reports ${NAME} where NAME is not set in the
	// environment and no fallback was given. The reference expands to the empty
	// string, which is rarely what the operator meant.
	WarnUndefinedVariable EnvWarningKind = "undefined_variable"
	// WarnUnterminatedRef reports a "${" that is never closed on its line. The
	// text is left exactly as written.
	WarnUnterminatedRef EnvWarningKind = "unterminated_reference"
	// WarnInvalidVariableName reports a reference whose body is not a valid
	// variable name, such as ${1FOO} or an unsupported shell form like
	// ${NAME:?message}. The text is left exactly as written.
	WarnInvalidVariableName EnvWarningKind = "invalid_variable_name"
	// WarnUnexpandedDollar reports a bare $NAME sequence that names a variable
	// which *is* set in the environment. os.ExpandEnv used to expand these;
	// Bifrost no longer does, so this is the one case where the change of
	// behavior can be noticed. The variable name is deliberately not recorded:
	// the surrounding text is operator data and may be a secret.
	WarnUnexpandedDollar EnvWarningKind = "unexpanded_dollar"
)

// EnvWarning is a non-fatal diagnostic produced by environment-variable
// expansion. It carries a line number and, where safe, a variable name; it
// never carries config file content, which may include secrets.
type EnvWarning struct {
	Kind EnvWarningKind
	// Name is the referenced variable name, or "" when naming it could
	// disclose config content (see WarnUnexpandedDollar).
	Name string
	Line int
}

// Message returns a human-readable description of the warning.
func (w EnvWarning) Message() string {
	switch w.Kind {
	case WarnUndefinedVariable:
		return "environment variable referenced by config is not set; expanded to an empty string (use ${NAME:-fallback} for a default)"
	case WarnUnterminatedRef:
		return "config contains an unterminated \"${\" reference; left as a literal (use " + envEscapeSequence + "{ for a literal \"${\")"
	case WarnInvalidVariableName:
		return "config contains a variable reference that is not a valid ${NAME} or ${NAME:-fallback} form; left as a literal"
	case WarnUnexpandedDollar:
		return "config contains a bare \"$NAME\" that matches a set environment variable; bare references are no longer expanded, use ${NAME} to expand it"
	default:
		return fmt.Sprintf("config environment expansion warning: %s", w.Kind)
	}
}

// ExpandEnvRefs expands ${NAME} and ${NAME:-fallback} references in raw
// configuration bytes and unescapes "$$" to "$". It returns the expanded bytes
// and any non-fatal diagnostics; it never fails, so a malformed reference is
// left verbatim rather than dropping operator data.
func ExpandEnvRefs(data []byte) ([]byte, []EnvWarning) {
	return expandEnvRefs(data, os.LookupEnv)
}

// EscapeEnvRefs escapes dollar signs in data so that ExpandEnvRefs reproduces
// it byte for byte. Only a dollar sign that would otherwise open a reference or
// an escape sequence is doubled, which keeps common values such as bcrypt
// hashes ("$2a$10$...") readable in the saved file.
func EscapeEnvRefs(data []byte) []byte {
	out := make([]byte, 0, len(data))
	for i := 0; i < len(data); i++ {
		c := data[i]
		if c == envDollar && i+1 < len(data) && (data[i+1] == envRefOpen || data[i+1] == envDollar) {
			out = append(out, envDollar)
		}
		out = append(out, c)
	}
	return out
}

// expandEnvRefs is ExpandEnvRefs with an injectable lookup, for testing.
func expandEnvRefs(data []byte, lookup func(string) (string, bool)) ([]byte, []EnvWarning) {
	var (
		out      = make([]byte, 0, len(data))
		warnings []EnvWarning
		line     = 1
	)

	for i := 0; i < len(data); {
		c := data[i]

		switch {
		case c == envNewline:
			line++
			out = append(out, c)
			i++

		case c != envDollar:
			out = append(out, c)
			i++

		// "$$" -> literal "$"
		case i+1 < len(data) && data[i+1] == envDollar:
			out = append(out, envDollar)
			i += 2

		// "${...}"
		case i+1 < len(data) && data[i+1] == envRefOpen:
			end := indexOnLine(data, i+2, envRefClose)
			if end < 0 {
				warnings = append(warnings, EnvWarning{Kind: WarnUnterminatedRef, Line: line})
				out = append(out, c)
				i++
				continue
			}

			name, fallback, hasFallback := splitEnvRef(string(data[i+2 : end]))
			if !isValidEnvName(name) {
				warnings = append(warnings, EnvWarning{Kind: WarnInvalidVariableName, Line: line})
				out = append(out, data[i:end+1]...)
				i = end + 1
				continue
			}

			value, set := lookup(name)
			switch {
			case hasFallback && (!set || value == ""):
				value = fallback
			case !set:
				warnings = append(warnings, EnvWarning{Kind: WarnUndefinedVariable, Name: name, Line: line})
			}

			out = append(out, value...)
			// A substituted value may itself span lines; keep the line counter
			// honest so later diagnostics point at the right place.
			line += strings.Count(value, "\n")
			i = end + 1

		// Bare "$NAME": left literal. Warn only when the name resolves, which
		// is a strong hint the operator expected the old os.ExpandEnv behavior.
		default:
			if name := scanEnvName(data[i+1:]); name != "" {
				if _, set := lookup(name); set {
					warnings = append(warnings, EnvWarning{Kind: WarnUnexpandedDollar, Line: line})
				}
			}
			out = append(out, c)
			i++
		}
	}

	return out, warnings
}

// indexOnLine returns the index of the first occurrence of b at or after start,
// or -1 if a newline or the end of data comes first.
func indexOnLine(data []byte, start int, b byte) int {
	for i := start; i < len(data); i++ {
		switch data[i] {
		case b:
			return i
		case envNewline:
			return -1
		}
	}
	return -1
}

// splitEnvRef splits a reference body into a variable name and an optional
// fallback value.
func splitEnvRef(body string) (name, fallback string, hasFallback bool) {
	if idx := strings.Index(body, envDefaultSeparator); idx >= 0 {
		return body[:idx], body[idx+len(envDefaultSeparator):], true
	}
	return body, "", false
}

// isValidEnvName reports whether s is a portable environment variable name.
func isValidEnvName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '_':
		case c >= '0' && c <= '9':
			if i == 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// scanEnvName returns the leading portable variable name in data, or "" if data
// does not start with one.
func scanEnvName(data []byte) string {
	end := 0
	for end < len(data) {
		c := data[end]
		isLetter := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_'
		isDigit := c >= '0' && c <= '9'
		if !isLetter && !(isDigit && end > 0) {
			break
		}
		end++
	}
	return string(data[:end])
}
