package auth

import (
	"fmt"
	"sort"

	"github.com/rennerdo30/bifrost-proxy/internal/config"
)

// The prototypes below enumerate, per auth provider type, exactly the keys the
// plugin reads out of auth.providers[].config — including nested objects and
// lists. yaml.v3's KnownFields cannot look into a map[string]any field, so
// before this check a typo like `disabledd: true` on a native user loaded
// silently and the supposedly disabled user kept authenticating: the exact
// fail-open the strict loader exists to prevent. Every key a plugin starts or
// stops reading must be mirrored here.
//
// Values are irrelevant (only keys and shape are checked), so scalar fields
// are typed loosely where the plugin tolerates it.

type nativeUserKeys struct {
	Username     string   `yaml:"username"`
	PasswordHash string   `yaml:"password_hash"`
	Groups       []string `yaml:"groups"`
	Email        string   `yaml:"email"`
	FullName     string   `yaml:"full_name"`
	Disabled     bool     `yaml:"disabled"`
}

type nativeKeys struct {
	Users []nativeUserKeys `yaml:"users"`
}

type apikeyEntryKeys struct {
	Name      string   `yaml:"name"`
	KeyHash   string   `yaml:"key_hash"`
	KeyPlain  string   `yaml:"key_plain"`
	Groups    []string `yaml:"groups"`
	Disabled  bool     `yaml:"disabled"`
	ExpiresAt string   `yaml:"expires_at"`
}

type apikeyKeys struct {
	HeaderName string            `yaml:"header_name"`
	Keys       []apikeyEntryKeys `yaml:"keys"`
}

type otpSecretKeys struct {
	Username string   `yaml:"username"`
	Secret   string   `yaml:"secret"`
	Counter  int64    `yaml:"counter"`
	Groups   []string `yaml:"groups"`
	Disabled bool     `yaml:"disabled"`
}

type totpKeys struct {
	Algorithm   string          `yaml:"algorithm"`
	Digits      int             `yaml:"digits"`
	Issuer      string          `yaml:"issuer"`
	Period      int             `yaml:"period"`
	Skew        int             `yaml:"skew"`
	Secrets     []otpSecretKeys `yaml:"secrets"`
	SecretsFile string          `yaml:"secrets_file"`
}

type hotpKeys struct {
	Algorithm   string          `yaml:"algorithm"`
	Digits      int             `yaml:"digits"`
	LookAhead   int             `yaml:"look_ahead"`
	Secrets     []otpSecretKeys `yaml:"secrets"`
	SecretsFile string          `yaml:"secrets_file"`
}

type jwtKeys struct {
	Algorithms          []string `yaml:"algorithms"`
	Audience            string   `yaml:"audience"`
	EmailClaim          string   `yaml:"email_claim"`
	GroupsClaim         string   `yaml:"groups_claim"`
	HMACSecret          string   `yaml:"hmac_secret"`
	Issuer              string   `yaml:"issuer"`
	JWKSRefreshInterval string   `yaml:"jwks_refresh_interval"`
	JWKSURL             string   `yaml:"jwks_url"`
	LeewaySeconds       int      `yaml:"leeway_seconds"`
	PublicKeyPEM        string   `yaml:"public_key_pem"`
	UsernameClaim       string   `yaml:"username_claim"`
}

type kerberosKeys struct {
	KDCServers          []string `yaml:"kdc_servers"`
	KeytabFile          string   `yaml:"keytab_file"`
	KeytabBase64        string   `yaml:"keytab_base64"`
	Krb5Config          string   `yaml:"krb5_config"`
	Krb5ConfigFile      string   `yaml:"krb5_config_file"`
	Realm               string   `yaml:"realm"`
	ServicePrincipal    string   `yaml:"service_principal"`
	StripRealm          bool     `yaml:"strip_realm"`
	UsernameToLowercase bool     `yaml:"username_to_lowercase"`
}

type ldapKeys struct {
	URL                   string `yaml:"url"`
	BaseDN                string `yaml:"base_dn"`
	BindDN                string `yaml:"bind_dn"`
	BindPassword          string `yaml:"bind_password"`
	UserAttribute         string `yaml:"user_attribute"`
	UserFilter            string `yaml:"user_filter"`
	GroupAttribute        string `yaml:"group_attribute"`
	GroupFilter           string `yaml:"group_filter"`
	GroupLookupFailClosed bool   `yaml:"group_lookup_fail_closed"`
	RequireGroup          string `yaml:"require_group"`
	EmailAttribute        string `yaml:"email_attribute"`
	FullNameAttribute     string `yaml:"full_name_attribute"`
	TLS                   bool   `yaml:"tls"`
	InsecureSkipVerify    bool   `yaml:"insecure_skip_verify"`
}

type mtlsSubjectMappingKeys struct {
	UsernameField string `yaml:"username_field"`
	EmailField    string `yaml:"email_field"`
	GroupsField   string `yaml:"groups_field"`
}

type mtlsKeys struct {
	AllowAnonymous    bool                   `yaml:"allow_anonymous"`
	AllowedIssuers    []string               `yaml:"allowed_issuers"`
	AllowedSubjects   []string               `yaml:"allowed_subjects"`
	CACertFile        string                 `yaml:"ca_cert_file"`
	CACertPEM         string                 `yaml:"ca_cert_pem"`
	CRLFile           string                 `yaml:"crl_file"`
	RequireClientCert bool                   `yaml:"require_client_cert"`
	SubjectMapping    mtlsSubjectMappingKeys `yaml:"subject_mapping"`
	VerifyTime        string                 `yaml:"verify_time"`
}

type ntlmKeys struct {
	AllowedDomains        []string `yaml:"allowed_domains"`
	Domain                string   `yaml:"domain"`
	ServerChallengeSecret string   `yaml:"server_challenge_secret"`
	StripDomain           bool     `yaml:"strip_domain"`
	UsernameToLowercase   bool     `yaml:"username_to_lowercase"`
}

type oauthKeys struct {
	ClientID       string         `yaml:"client_id"`
	ClientSecret   string         `yaml:"client_secret"`
	IntrospectURL  string         `yaml:"introspect_url"`
	IssuerURL      string         `yaml:"issuer_url"`
	Provider       string         `yaml:"provider"`
	RequiredClaims map[string]any `yaml:"required_claims"`
	Scopes         []string       `yaml:"scopes"`
	UserinfoURL    string         `yaml:"userinfo_url"`
}

type systemKeys struct {
	AllowedGroups []string `yaml:"allowed_groups"`
	AllowedUsers  []string `yaml:"allowed_users"`
	Domain        string   `yaml:"domain"`
	LogonType     string   `yaml:"logon_type"`
	Service       string   `yaml:"service"`
}

// mfaInlineKeys is one of the mfa_wrapper's inline primary/secondary blocks.
// The inner config is a dynamic map for ANOTHER plugin type; it is validated
// recursively against that plugin's own schema in validateMFAWrapperKeys.
type mfaInlineKeys struct {
	Mode   string         `yaml:"mode"`
	Config map[string]any `yaml:"config"`
}

type mfaWrapperKeys struct {
	Primary         *mfaInlineKeys `yaml:"primary"`
	Secondary       *mfaInlineKeys `yaml:"secondary"`
	PrimaryProvider string         `yaml:"primary_provider"`
	MFAProvider     string         `yaml:"mfa_provider"`
	MFAType         string         `yaml:"mfa_type"`
	MFARequired     string         `yaml:"mfa_required"`
	MFAGroups       []string       `yaml:"mfa_groups"`
	MFAUsers        []string       `yaml:"mfa_users"`
	PasswordFormat  string         `yaml:"password_format"`
	Separator       string         `yaml:"separator"`
	MFACodeLength   int            `yaml:"mfa_code_length"`
}

type noneKeys struct{}

// providerPrototypes maps every registered provider type to a fresh prototype
// for strict key validation.
var providerPrototypes = map[string]func() any{
	"native":      func() any { return &nativeKeys{} },
	"apikey":      func() any { return &apikeyKeys{} },
	"totp":        func() any { return &totpKeys{} },
	"hotp":        func() any { return &hotpKeys{} },
	"jwt":         func() any { return &jwtKeys{} },
	"kerberos":    func() any { return &kerberosKeys{} },
	"ldap":        func() any { return &ldapKeys{} },
	"mtls":        func() any { return &mtlsKeys{} },
	"ntlm":        func() any { return &ntlmKeys{} },
	"oauth":       func() any { return &oauthKeys{} },
	"system":      func() any { return &systemKeys{} },
	"mfa_wrapper": func() any { return &mfaWrapperKeys{} },
	"none":        func() any { return &noneKeys{} },
}

// SchemaTypes returns every provider type with a key schema, sorted, so tests
// can prove the registry and the plugin registrations stay in lockstep.
func SchemaTypes() []string {
	types := make([]string, 0, len(providerPrototypes))
	for t := range providerPrototypes {
		types = append(types, t)
	}
	sort.Strings(types)
	return types
}

// ValidateProviderKeys rejects unknown keys in a provider's dynamic config
// block, recursing into the mfa_wrapper's inline authenticator blocks. It runs
// wherever providers are validated or created, so a typo cannot fail open.
func ValidateProviderKeys(providerType string, cfg map[string]any) error {
	prototype, ok := providerPrototypes[providerType]
	if !ok {
		// Unknown types are rejected elsewhere with plugin guidance; the key
		// schema has nothing to add for them.
		return nil
	}
	section := fmt.Sprintf("auth provider type %s config", providerType)
	if err := config.ValidateKnownKeys(section, cfg, prototype()); err != nil {
		return err
	}
	if providerType == "mfa_wrapper" {
		return validateMFAWrapperInlineKeys(cfg)
	}
	return nil
}

// validateMFAWrapperInlineKeys validates the dynamic inner config of each
// inline primary/secondary block against the inner plugin type's own schema.
func validateMFAWrapperInlineKeys(cfg map[string]any) error {
	for _, block := range []string{"primary", "secondary"} {
		inline, ok := cfg[block].(map[string]any)
		if !ok {
			continue
		}
		mode, _ := inline["mode"].(string) //nolint:errcheck // missing mode is rejected by the plugin itself
		innerCfg, _ := inline["config"].(map[string]any)
		if mode == "" || innerCfg == nil {
			continue
		}
		if err := ValidateProviderKeys(mode, innerCfg); err != nil {
			return fmt.Errorf("mfa_wrapper %s block: %w", block, err)
		}
	}
	return nil
}
