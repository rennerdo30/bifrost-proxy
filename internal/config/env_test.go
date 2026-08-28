package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeEnv builds a lookup function over a fixed map so expansion tests do not
// depend on the ambient environment.
func fakeEnv(vars map[string]string) func(string) (string, bool) {
	return func(name string) (string, bool) {
		v, ok := vars[name]
		return v, ok
	}
}

func TestExpandEnvRefs_Table(t *testing.T) {
	env := map[string]string{
		"PORT":     "9999",
		"EMPTY":    "",
		"PASSWORD": "s3cr$et",
		"MULTI":    "a\nb",
	}

	tests := []struct {
		name     string
		in       string
		want     string
		wantKind []EnvWarningKind
		wantLine []int
	}{
		{
			name: "braced reference expands",
			in:   "listen: \":${PORT}\"",
			want: "listen: \":9999\"",
		},
		{
			name: "reference is the whole value",
			in:   "port: ${PORT}",
			want: "port: 9999",
		},
		{
			name: "several references on one line",
			in:   "addr: ${PORT}:${PORT}",
			want: "addr: 9999:9999",
		},
		// The defect: os.ExpandEnv truncated any value containing "$word".
		{
			name: "dollar in the middle of a value is literal",
			in:   "password: p@ss$word123",
			want: "password: p@ss$word123",
		},
		{
			name: "dollar at the start of a value is literal",
			in:   "password: $word123",
			want: "password: $word123",
		},
		{
			name: "dollar at the end of a value is literal",
			in:   "password: word123$",
			want: "password: word123$",
		},
		{
			name: "bcrypt hash survives untouched",
			in:   "password_hash: $2a$10$N9qo8uLOickgx2ZMRZoMye",
			want: "password_hash: $2a$10$N9qo8uLOickgx2ZMRZoMye",
		},
		{
			name: "dollar followed by punctuation is literal",
			in:   "password: a$-b$.c",
			want: "password: a$-b$.c",
		},
		{
			name: "double dollar escapes to a single dollar",
			in:   "password: a$${PORT}b",
			want: "password: a${PORT}b",
		},
		{
			name: "escaped dollar before another dollar",
			in:   "password: a$$$$b",
			want: "password: a$$b",
		},
		{
			name: "default form is honored",
			in:   "listen: \":${HTTP_PORT:-8080}\"",
			want: "listen: \":8080\"",
		},
		{
			name: "default form prefers the set variable",
			in:   "listen: \":${PORT:-8080}\"",
			want: "listen: \":9999\"",
		},
		{
			name: "default form replaces an empty variable",
			in:   "level: ${EMPTY:-info}",
			want: "level: info",
		},
		{
			name: "empty default is allowed",
			in:   "level: \"${MISSING:-}\"",
			want: "level: \"\"",
		},
		{
			name: "default containing a colon",
			in:   "addr: ${MISSING:-host:7080}",
			want: "addr: host:7080",
		},
		{
			name:     "unset variable warns and expands empty",
			in:       "listen: \":${MISSING}\"",
			want:     "listen: \":\"",
			wantKind: []EnvWarningKind{WarnUndefinedVariable},
			wantLine: []int{1},
		},
		{
			name:     "unterminated reference is left literal",
			in:       "password: a${PORT\nnext: 1",
			want:     "password: a${PORT\nnext: 1",
			wantKind: []EnvWarningKind{WarnUnterminatedRef},
			wantLine: []int{1},
		},
		{
			name:     "reference may not span lines",
			in:       "password: a${PORT\n}x",
			want:     "password: a${PORT\n}x",
			wantKind: []EnvWarningKind{WarnUnterminatedRef},
			wantLine: []int{1},
		},
		{
			name:     "invalid variable name is left literal",
			in:       "password: ${1PORT}",
			want:     "password: ${1PORT}",
			wantKind: []EnvWarningKind{WarnInvalidVariableName},
			wantLine: []int{1},
		},
		{
			name:     "unsupported shell form is left literal",
			in:       "password: ${PORT:?required}",
			want:     "password: ${PORT:?required}",
			wantKind: []EnvWarningKind{WarnInvalidVariableName},
			wantLine: []int{1},
		},
		{
			name:     "empty reference body is left literal",
			in:       "password: ${}",
			want:     "password: ${}",
			wantKind: []EnvWarningKind{WarnInvalidVariableName},
			wantLine: []int{1},
		},
		{
			name:     "bare reference to a set variable warns",
			in:       "listen: :$PORT",
			want:     "listen: :$PORT",
			wantKind: []EnvWarningKind{WarnUnexpandedDollar},
			wantLine: []int{1},
		},
		{
			name: "bare reference to an unset variable is silent",
			in:   "password: p@ss$word123",
			want: "password: p@ss$word123",
		},
		{
			name:     "warning line numbers count newlines",
			in:       "a: 1\nb: ${MISSING}\nc: 3\nd: ${MISSING}\n",
			want:     "a: 1\nb: \nc: 3\nd: \n",
			wantKind: []EnvWarningKind{WarnUndefinedVariable, WarnUndefinedVariable},
			wantLine: []int{2, 4},
		},
		{
			name:     "line numbers survive a multi-line value",
			in:       "a: ${MULTI}\nb: ${MISSING}\n",
			want:     "a: a\nb\nb: \n",
			wantKind: []EnvWarningKind{WarnUndefinedVariable},
			wantLine: []int{3},
		},
		{
			name: "expansion is not recursive",
			in:   "password: ${PASSWORD}",
			want: "password: s3cr$et",
		},
		{
			name: "empty input",
			in:   "",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, warnings := expandEnvRefs([]byte(tt.in), fakeEnv(env))
			assert.Equal(t, tt.want, string(got))

			kinds := make([]EnvWarningKind, 0, len(warnings))
			lines := make([]int, 0, len(warnings))
			for _, w := range warnings {
				kinds = append(kinds, w.Kind)
				lines = append(lines, w.Line)
				assert.NotEmpty(t, w.Message(), "every warning must carry a message")
			}
			if len(tt.wantKind) == 0 {
				assert.Empty(t, kinds, "expected no warnings")
			} else {
				assert.Equal(t, tt.wantKind, kinds)
				assert.Equal(t, tt.wantLine, lines)
			}
		})
	}
}

func TestExpandEnvRefs_UndefinedWarningNamesTheVariable(t *testing.T) {
	_, warnings := expandEnvRefs([]byte("token: ${API_TOKEN}"), fakeEnv(nil))
	require.Len(t, warnings, 1)
	assert.Equal(t, "API_TOKEN", warnings[0].Name)
}

// The bare-dollar warning must never carry the surrounding text or the parsed
// name: "$word123" is a fragment of a password, not a variable the operator
// chose to name.
func TestExpandEnvRefs_UnexpandedDollarWarningCarriesNoSecret(t *testing.T) {
	_, warnings := expandEnvRefs([]byte("password: p@ss$word123"), fakeEnv(map[string]string{"word123": "x"}))
	require.Len(t, warnings, 1)
	assert.Equal(t, WarnUnexpandedDollar, warnings[0].Kind)
	assert.Empty(t, warnings[0].Name)
	assert.NotContains(t, warnings[0].Message(), "word123")
}

func TestExpandEnvRefs_UsesProcessEnvironment(t *testing.T) {
	t.Setenv("BIFROST_TEST_EXPAND", "expanded")
	got, warnings := ExpandEnvRefs([]byte("value: ${BIFROST_TEST_EXPAND}"))
	assert.Equal(t, "value: expanded", string(got))
	assert.Empty(t, warnings)
}

func TestEscapeEnvRefs_RoundTrip(t *testing.T) {
	values := []string{
		"p@ss$word123",
		"$2a$10$N9qo8uLOickgx2ZMRZoMye",
		"a${PORT}b",
		"a$${PORT}b",
		"$$",
		"$",
		"${",
		"plain",
		"trailing$",
	}

	for _, v := range values {
		t.Run(v, func(t *testing.T) {
			escaped := EscapeEnvRefs([]byte(v))
			got, warnings := expandEnvRefs(escaped, fakeEnv(map[string]string{"PORT": "9999"}))
			assert.Equal(t, v, string(got), "escaped value must expand back to itself")
			assert.Empty(t, warnings)
		})
	}
}

func TestEscapeEnvRefs_LeavesHarmlessDollarsAlone(t *testing.T) {
	// Readability matters: bcrypt hashes must not be peppered with "$$".
	assert.Equal(t, "$2a$10$abc", string(EscapeEnvRefs([]byte("$2a$10$abc"))))
}

func TestIsValidEnvName(t *testing.T) {
	valid := []string{"A", "_", "PORT", "HTTP_PORT", "a1", "_1"}
	invalid := []string{"", "1PORT", "A B", "A-B", "A.B", "PORT:", "ünicode"}

	for _, s := range valid {
		assert.True(t, isValidEnvName(s), "%q should be valid", s)
	}
	for _, s := range invalid {
		assert.False(t, isValidEnvName(s), "%q should be invalid", s)
	}
}

func TestScanEnvName(t *testing.T) {
	assert.Equal(t, "PORT", scanEnvName([]byte("PORT}")))
	assert.Equal(t, "word123", scanEnvName([]byte("word123 ")))
	assert.Equal(t, "", scanEnvName([]byte("1abc")))
	assert.Equal(t, "", scanEnvName([]byte("")))
	assert.Equal(t, "", scanEnvName([]byte("-x")))
}

func TestEnvWarning_MessageForUnknownKind(t *testing.T) {
	w := EnvWarning{Kind: EnvWarningKind("something_else"), Line: 7}
	assert.Contains(t, w.Message(), "something_else")
}
