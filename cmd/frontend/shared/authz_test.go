package shared

import (
	"context"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/sourcegraph/sourcegraph/cmd/frontend/external/auth"
	"github.com/sourcegraph/sourcegraph/cmd/frontend/internal/authz"
	"github.com/sourcegraph/sourcegraph/cmd/frontend/internal/authz/gitlab"
	"github.com/sourcegraph/sourcegraph/cmd/frontend/types"
	"github.com/sourcegraph/sourcegraph/pkg/api"
	"github.com/sourcegraph/sourcegraph/pkg/extsvc"
	"github.com/sourcegraph/sourcegraph/schema"
)

type newGitLabAuthzProviderParams struct {
	Op gitlab.GitLabAuthzProviderOp
}

func (m newGitLabAuthzProviderParams) RepoPerms(ctx context.Context, account *extsvc.ExternalAccount, repos map[authz.Repo]struct{}) (map[api.RepoURI]map[authz.Perm]bool, error) {
	panic("should never be called")
}
func (m newGitLabAuthzProviderParams) Repos(ctx context.Context, repos map[authz.Repo]struct{}) (mine map[authz.Repo]struct{}, others map[authz.Repo]struct{}) {
	panic("should never be called")
}
func (m newGitLabAuthzProviderParams) FetchAccount(ctx context.Context, user *types.User, current []*extsvc.ExternalAccount) (mine *extsvc.ExternalAccount, err error) {
	panic("should never be called")
}
func (m newGitLabAuthzProviderParams) ServiceID() string {
	panic("should never be called")
}
func (m newGitLabAuthzProviderParams) ServiceType() string {
	panic("should never be called")
}

func Test_providersFromConfig(t *testing.T) {
	NewGitLabAuthzProvider = func(op gitlab.GitLabAuthzProviderOp) authz.AuthzProvider {
		op.MockCache = nil // ignore cache value
		return newGitLabAuthzProviderParams{op}
	}

	tests := []struct {
		description                  string
		cfg                          schema.SiteConfiguration
		expPermissionsAllowByDefault bool
		expAuthzProviders            []authz.AuthzProvider
		expSeriousProblems           []string
		expWarnings                  []string
	}{
		{
			description: "standard config pointing to okta",
			cfg: schema.SiteConfiguration{
				AuthProviders: []schema.AuthProviders{
					schema.AuthProviders{
						Saml: &schema.SAMLAuthProvider{
							ConfigID: "okta-config-id",
							Type:     "saml",
						},
					},
				},
				Gitlab: []*schema.GitLabConnection{{
					Authz: &schema.Authz{
						AuthnProvider: schema.AuthnProvider{
							ConfigID:       "okta-config-id",
							Type:           "saml",
							GitlabProvider: "okta",
						},
						Matcher: "gitlab.mine/*",
						Ttl:     "48h",
					},
					RepositoryPathPattern: "{host}-{pathWithNamespace}",
					Url:                   "https://gitlab.mine",
					Token:                 "asdf",
				}},
			},
			expPermissionsAllowByDefault: true,
			expAuthzProviders: []authz.AuthzProvider{
				newGitLabAuthzProviderParams{
					Op: gitlab.GitLabAuthzProviderOp{
						BaseURL:         mustURLParse(t, "https://gitlab.mine"),
						AuthnConfigID:   auth.ProviderConfigID{Type: "saml", ID: "okta-config-id"},
						SudoToken:       "asdf",
						GitLabProvider:  "okta",
						RepoPathPattern: "{host}-{pathWithNamespace}",
						MatchPattern:    "gitlab.mine/*",
						CacheTTL:        48 * time.Hour,
					},
				},
			},
			expSeriousProblems: nil,
			expWarnings:        nil,
		},
		/*
			{
				description: "standard config pointing to okta, with RepositoryPathPattern",
				cfg: schema.SiteConfiguration{
					Gitlab: []*schema.GitLabConnection{{
						PermissionsIgnore:  false,
						PermissionsMatcher: "asdf/gitlab.mine/*",
						PermissionsTtl:     "48h",
						PermissionsAuthnProvider: &schema.PermissionsAuthnProvider{
							ServiceID:      "https://okta.mine/",
							Type:           "saml",
							GitlabProvider: "okta",
						},
						RepositoryPathPattern: "asdf/{host}/{pathWithNamespace}",
						Url:                   "https://gitlab.mine",
						Token:                 "asdf",
					}},
				},
				expPermissionsAllowByDefault: true,
				expAuthzProviders: []authz.AuthzProvider{
					newGitLabAuthzProviderParams{
						Op: gitlab.GitLabAuthzProviderOp{
							BaseURL:                  mustURLParse(t, "https://gitlab.mine"),
							IdentityServiceID:        "https://okta.mine/",
							IdentityServiceType:      "saml",
							GitLabIdentityProviderID: "okta",
							MatchPattern:             "asdf/gitlab.mine/*",
							RepoPathPattern:          "asdf/{host}/{pathWithNamespace}",
							SudoToken:                "asdf",
							CacheTTL:                 48 * time.Hour,
						},
					},
				},
				expSeriousProblems: nil,
				expWarnings:        nil,
			},
			{
				description: "pointing to okta, no matcher, no ttl",
				cfg: schema.SiteConfiguration{
					Gitlab: []*schema.GitLabConnection{{
						PermissionsIgnore:  false,
						PermissionsMatcher: "",
						PermissionsAuthnProvider: &schema.PermissionsAuthnProvider{
							ServiceID:      "https://okta.mine/",
							Type:           "saml",
							GitlabProvider: "okta",
						},
						Url:   "https://gitlab.mine",
						Token: "asdf",
					}},
				},
				expPermissionsAllowByDefault: true,
				expAuthzProviders: []authz.AuthzProvider{
					newGitLabAuthzProviderParams{
						Op: gitlab.GitLabAuthzProviderOp{
							BaseURL:                  mustURLParse(t, "https://gitlab.mine"),
							IdentityServiceID:        "https://okta.mine/",
							IdentityServiceType:      "saml",
							GitLabIdentityProviderID: "okta",
							SudoToken:                "asdf",
							CacheTTL:                 3 * time.Hour,
						},
					},
				},
				expSeriousProblems: nil,
				expWarnings:        nil,
			},
			{
				description: "no authn provider specified",
				cfg: schema.SiteConfiguration{
					Gitlab: []*schema.GitLabConnection{{
						PermissionsIgnore: false,
						Url:               "https://gitlab.mine",
						Token:             "asdf",
					}},
				},
				expPermissionsAllowByDefault: false,
				expAuthzProviders: []authz.AuthzProvider{
					newGitLabAuthzProviderParams{
						Op: gitlab.GitLabAuthzProviderOp{
							BaseURL:           mustURLParse(t, "https://gitlab.mine"),
							SudoToken:         "asdf",
							CacheTTL:          3 * time.Hour,
							UseNativeUsername: true,
						},
					},
				},
				expSeriousProblems: []string{"No `permissions.authnProvider` specified for GitLab connection. Falling back to using username matching, which is insecure."},
			},
			{
				description: "invalid url",
				cfg: schema.SiteConfiguration{
					Gitlab: []*schema.GitLabConnection{{
						PermissionsIgnore: false,
						Url:               "http://not a url",
					}},
				},
				expPermissionsAllowByDefault: false,
				expAuthzProviders:            nil,
				expSeriousProblems: []string{
					`Could not parse URL for GitLab instance "http://not a url": parse http://not a url: invalid character " " in host name`,
				},
				expWarnings: nil,
			},
			{
				description: "ignore permissions",
				cfg: schema.SiteConfiguration{
					Gitlab: []*schema.GitLabConnection{{
						PermissionsIgnore: true,
						Url:               "https://gitlab.mine",
					}},
				},
				expPermissionsAllowByDefault: true,
				expAuthzProviders:            nil,
				expSeriousProblems:           nil,
				expWarnings:                  nil,
			},
		*/
	}

	// TODO: test case for no PermissionsAuthnProvider

	for _, test := range tests {
		permissionsAllowByDefault, authzProviders, seriousProblems, warnings := providersFromConfig(&test.cfg)
		if permissionsAllowByDefault != test.expPermissionsAllowByDefault {
			t.Errorf("permissionsAllowByDefault: (actual) %v != (expected) %v", permissionsAllowByDefault, test.expPermissionsAllowByDefault)
		}
		if !reflect.DeepEqual(authzProviders, test.expAuthzProviders) {
			t.Errorf("authzProviders: (actual) %+v != (expected) %+v", authzProviders, test.expAuthzProviders)
		}
		if !reflect.DeepEqual(seriousProblems, test.expSeriousProblems) {
			t.Errorf("seriousProblems: (actual) %+v != (expected) %+v", seriousProblems, test.expSeriousProblems)
		}
		if !reflect.DeepEqual(warnings, test.expWarnings) {
			t.Errorf("warnings: (actual) %+v != (expected) %+v", warnings, test.expWarnings)
		}
	}
}

func mustURLParse(t *testing.T, u string) *url.URL {
	parsed, err := url.Parse(u)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

// type mockAuthnProvider struct {
// 	configID auth.ProviderConfigID
// }

// var _ auth.Provider = mockAuthnProvider{}

// func (m mockAuthnProvider) ConfigID() auth.ProviderConfigID {
// 	return m.configID
// }

// func (m mockAuthnProvider) Config() schema.AuthProviders {
// 	panic("should not be called")
// }

// func (m mockAuthnProvider) CachedInfo() *auth.ProviderInfo {
// 	panic("should not be called")
// }

// func (m mockAuthnProvider) Refresh(ctx context.Context) error {
// 	panic("should not be called")
// }

// func mustURL(t *testing.T, u string) *url.URL {
// 	parsed, err := url.Parse(u)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	return parsed
// }
