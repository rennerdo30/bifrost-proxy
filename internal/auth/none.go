package auth

import "context"

// NoneAuthenticator allows all requests without authentication.
type NoneAuthenticator struct{}

// NewNoneAuthenticator creates a new none authenticator.
func NewNoneAuthenticator() *NoneAuthenticator {
	return &NoneAuthenticator{}
}

// Authenticate always succeeds for none auth.
func (a *NoneAuthenticator) Authenticate(ctx context.Context, username, password string) (*UserInfo, error) {
	return &UserInfo{
		Username: "anonymous",
	}, nil
}

// Name returns the authenticator name.
func (a *NoneAuthenticator) Name() string {
	return "none"
}

// Type returns the authenticator type.
func (a *NoneAuthenticator) Type() string {
	return "none"
}
