package gitlab

import (
	"context"
	"net/url"
	"reflect"
	"strconv"
	"testing"

	"github.com/sourcegraph/sourcegraph/cmd/frontend/internal/auth"
	"github.com/sourcegraph/sourcegraph/cmd/frontend/internal/authz"
	"github.com/sourcegraph/sourcegraph/cmd/frontend/types"
	"github.com/sourcegraph/sourcegraph/pkg/api"
	"github.com/sourcegraph/sourcegraph/pkg/extsvc"
	"github.com/sourcegraph/sourcegraph/pkg/extsvc/gitlab"
	"github.com/sourcegraph/sourcegraph/schema"
)

func Test_GitLab_FetchAccount(t *testing.T) {
	tests := []GitLab_FetchAccount_Test{
		{
			description: "1 authn provider, basic authz provider",
			authnProviders: []auth.Provider{
				mockAuthnProvider{
					configID:  auth.ProviderConfigID{ID: "okta.mine", Type: "saml"},
					serviceID: "https://okta.mine/",
				},
			},
			op: GitLabAuthzProviderOp{
				BaseURL:           mustURL(t, "https://gitlab.mine"),
				AuthnConfigID:     auth.ProviderConfigID{ID: "okta.mine", Type: "saml"},
				GitLabProvider:    "okta.mine",
				UseNativeUsername: false,
			},
			calls: []GitLab_FetchAccount_Test_call{
				{
					description: "1 account, matches",
					user:        &types.User{ID: 123},
					current:     []*extsvc.ExternalAccount{acct(1, "saml", "https://okta.mine/", "bl")},
					expMine:     acct(123, gitlab.GitLabServiceType, "https://gitlab.mine/", "101"),
				},
				{
					description: "many accounts, none match",
					user:        &types.User{ID: 123},
					current: []*extsvc.ExternalAccount{
						acct(1, "saml", "https://okta.mine/", "nomatch"),
						acct(1, "saml", "nomatch", "bl"),
						acct(1, "nomatch", "https://okta.mine/", "bl"),
					},
					expMine: nil,
				},
				{
					description: "many accounts, 1 match",
					user:        &types.User{ID: 123},
					current: []*extsvc.ExternalAccount{
						acct(1, "saml", "nomatch", "bl"),
						acct(1, "nomatch", "https://okta.mine/", "bl"),
						acct(1, "saml", "https://okta.mine/", "bl"),
					},
					expMine: acct(123, gitlab.GitLabServiceType, "https://gitlab.mine/", "101"),
				},
				{
					description: "no user",
					user:        nil,
					current:     nil,
					expMine:     nil,
				},
			},
		},
		{
			description:    "0 authn providers, native username",
			authnProviders: nil,
			op: GitLabAuthzProviderOp{
				BaseURL:           mustURL(t, "https://gitlab.mine"),
				UseNativeUsername: true,
			},
			calls: []GitLab_FetchAccount_Test_call{
				{
					description: "username match",
					user:        &types.User{ID: 123, Username: "b.l"},
					expMine:     acct(123, gitlab.GitLabServiceType, "https://gitlab.mine/", "101"),
				},
				{
					description: "no username match",
					user:        &types.User{ID: 123, Username: "nomatch"},
					expMine:     nil,
				},
			},
		},
		{
			description:    "0 authn providers, basic authz provider",
			authnProviders: nil,
			op: GitLabAuthzProviderOp{
				BaseURL:           mustURL(t, "https://gitlab.mine"),
				AuthnConfigID:     auth.ProviderConfigID{ID: "okta.mine", Type: "saml"},
				GitLabProvider:    "okta.mine",
				UseNativeUsername: false,
			},
			calls: []GitLab_FetchAccount_Test_call{
				{
					description: "no matches",
					user:        &types.User{ID: 123, Username: "b.l"},
					expMine:     nil,
				},
			},
		},
		{
			description: "2 authn providers, basic authz provider",
			authnProviders: []auth.Provider{
				mockAuthnProvider{
					configID:  auth.ProviderConfigID{ID: "okta.mine", Type: "saml"},
					serviceID: "https://okta.mine/",
				},
				mockAuthnProvider{
					configID:  auth.ProviderConfigID{ID: "onelogin.mine", Type: "openidconnect"},
					serviceID: "https://onelogin.mine/",
				},
			},
			op: GitLabAuthzProviderOp{
				BaseURL:           mustURL(t, "https://gitlab.mine"),
				AuthnConfigID:     auth.ProviderConfigID{ID: "onelogin.mine", Type: "openidconnect"},
				GitLabProvider:    "onelogin.mine",
				UseNativeUsername: false,
			},
			calls: []GitLab_FetchAccount_Test_call{
				{
					description: "1 authn provider matches",
					user:        &types.User{ID: 123},
					current:     []*extsvc.ExternalAccount{acct(1, "openidconnect", "https://onelogin.mine/", "bl")},
					expMine:     acct(123, gitlab.GitLabServiceType, "https://gitlab.mine/", "101"),
				},
				{
					description: "0 authn providers match",
					user:        &types.User{ID: 123},
					current:     []*extsvc.ExternalAccount{acct(1, "openidconnect", "https://onelogin.mine/", "nomatch")},
					expMine:     nil,
				},
			},
		},
	}

	gitlabMock := mockGitLab{
		t:          t,
		maxPerPage: 1,
		users: []*gitlab.User{
			{
				ID:       101,
				Username: "b.l",
				Identities: []gitlab.Identity{
					{Provider: "okta.mine", ExternUID: "bl"},
					{Provider: "onelogin.mine", ExternUID: "bl"},
				},
			},
			{
				ID:         102,
				Username:   "k.l",
				Identities: []gitlab.Identity{{Provider: "okta.mine", ExternUID: "kl"}},
			},
			{
				ID:         199,
				Username:   "user-without-extern-id",
				Identities: nil,
			},
		},
	}
	gitlab.MockListUsers = gitlabMock.ListUsers

	for _, test := range tests {
		test.run(t)
	}
}

type GitLab_FetchAccount_Test struct {
	description string

	authnProviders []auth.Provider
	op             GitLabAuthzProviderOp

	calls []GitLab_FetchAccount_Test_call
}

type GitLab_FetchAccount_Test_call struct {
	description string

	user    *types.User
	current []*extsvc.ExternalAccount

	expMine *extsvc.ExternalAccount
}

func (g GitLab_FetchAccount_Test) run(t *testing.T) {
	t.Logf("Test case %q", g.description)

	provs := make(map[auth.Provider]bool)
	for _, p := range g.authnProviders {
		provs[p] = true
	}
	auth.UpdateProviders(provs)

	ctx := context.Background()
	authzProvider := NewGitLabAuthzProvider(g.op)
	for _, c := range g.calls {
		t.Logf("Call %q", c.description)
		acct, err := authzProvider.FetchAccount(ctx, c.user, c.current)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
			continue
		}
		if acct != nil {
			// ignore these fields for comparison
			acct.AuthData = nil
			acct.AccountData = nil
		}
		if !reflect.DeepEqual(acct, c.expMine) {
			t.Errorf("expected %+v, but got %+v", c.expMine, acct)
		}
	}
}

func Test_GitLab_RepoPerms(t *testing.T) {
	gitlabMock := mockGitLab{
		acls: map[string][]string{
			"101": []string{"bl/repo-1", "bl/repo-2", "bl/repo-3", "org/repo-1", "org/repo-2", "org/repo-3", "bl/a"},
			"102": []string{"kl/repo-1", "kl/repo-2", "kl/repo-3"},
		},
		projs: map[string]*gitlab.Project{
			"bl/repo-1":  &gitlab.Project{ProjectCommon: gitlab.ProjectCommon{PathWithNamespace: "bl/repo-1"}},
			"bl/repo-2":  &gitlab.Project{ProjectCommon: gitlab.ProjectCommon{PathWithNamespace: "bl/repo-2"}},
			"bl/repo-3":  &gitlab.Project{ProjectCommon: gitlab.ProjectCommon{PathWithNamespace: "bl/repo-3"}},
			"kl/repo-1":  &gitlab.Project{ProjectCommon: gitlab.ProjectCommon{PathWithNamespace: "kl/repo-1"}},
			"kl/repo-2":  &gitlab.Project{ProjectCommon: gitlab.ProjectCommon{PathWithNamespace: "kl/repo-2"}},
			"kl/repo-3":  &gitlab.Project{ProjectCommon: gitlab.ProjectCommon{PathWithNamespace: "kl/repo-3"}},
			"org/repo-1": &gitlab.Project{ProjectCommon: gitlab.ProjectCommon{PathWithNamespace: "org/repo-1"}},
			"org/repo-2": &gitlab.Project{ProjectCommon: gitlab.ProjectCommon{PathWithNamespace: "org/repo-2"}},
			"org/repo-3": &gitlab.Project{ProjectCommon: gitlab.ProjectCommon{PathWithNamespace: "org/repo-3"}},
			"bl/a":       &gitlab.Project{ProjectCommon: gitlab.ProjectCommon{PathWithNamespace: "bl/a"}},
		},
		t:          t,
		maxPerPage: 1,
	}
	gitlab.MockListProjects = gitlabMock.ListProjects

	tests := []GitLab_RepoPerms_Test{
		{
			description: "matchPattern",
			op: GitLabAuthzProviderOp{
				BaseURL:         mustURL(t, "https://gitlab.mine"),
				AuthnConfigID:   auth.ProviderConfigID{ID: "https://gitlab.mine/", Type: gitlab.GitLabServiceType},
				SudoToken:       "valid-sudo-token",
				RepoPathPattern: "{host}/{pathWithNamespace}",
				MatchPattern:    "gitlab.mine/*",
			},
			calls: []GitLab_RepoPerms_call{
				{
					description: "bl user has expected perms, short input repos list",
					account:     acct(1, gitlab.GitLabServiceType, "https://gitlab.mine/", "101"),
					repos: map[authz.Repo]struct{}{
						authz.Repo{URI: "gitlab.mine/bl/repo-1"}:  struct{}{},
						authz.Repo{URI: "gitlab.mine/kl/repo-1"}:  struct{}{},
						authz.Repo{URI: "gitlab.mine/org/repo-1"}: struct{}{},
						authz.Repo{URI: "part-of-gitlab.mine-but-doesn't-match-pattern", ExternalRepoSpec: api.ExternalRepoSpec{ServiceType: gitlab.GitLabServiceType, ServiceID: "https://gitlab.mine/"}}: struct{}{},
					},
					expPerms: map[api.RepoURI]map[authz.Perm]bool{
						"gitlab.mine/bl/repo-1":  map[authz.Perm]bool{authz.Read: true},
						"gitlab.mine/kl/repo-1":  map[authz.Perm]bool{},
						"gitlab.mine/org/repo-1": map[authz.Perm]bool{authz.Read: true},
					},
				},
				{
					description: "bl user has expected perms, long input repos list",
					account:     acct(1, gitlab.GitLabServiceType, "https://gitlab.mine/", "101"),
					repos: map[authz.Repo]struct{}{
						authz.Repo{URI: "gitlab.mine/bl/repo-1"}:  struct{}{},
						authz.Repo{URI: "gitlab.mine/bl/repo-2"}:  struct{}{},
						authz.Repo{URI: "gitlab.mine/bl/repo-3"}:  struct{}{},
						authz.Repo{URI: "gitlab.mine/kl/repo-1"}:  struct{}{},
						authz.Repo{URI: "gitlab.mine/kl/repo-2"}:  struct{}{},
						authz.Repo{URI: "gitlab.mine/kl/repo-3"}:  struct{}{},
						authz.Repo{URI: "gitlab.mine/org/repo-1"}: struct{}{},
						authz.Repo{URI: "gitlab.mine/org/repo-2"}: struct{}{},
						authz.Repo{URI: "gitlab.mine/org/repo-3"}: struct{}{},
						authz.Repo{URI: "gitlab.mine/bl/a"}:       struct{}{},
						authz.Repo{URI: "a", ExternalRepoSpec: api.ExternalRepoSpec{
							ServiceType: gitlab.GitLabServiceType,
							ServiceID:   "https://gitlab.mine/",
						}}: struct{}{},
					},
					expPerms: map[api.RepoURI]map[authz.Perm]bool{
						"gitlab.mine/bl/repo-1":  map[authz.Perm]bool{authz.Read: true},
						"gitlab.mine/bl/repo-2":  map[authz.Perm]bool{authz.Read: true},
						"gitlab.mine/bl/repo-3":  map[authz.Perm]bool{authz.Read: true},
						"gitlab.mine/kl/repo-1":  map[authz.Perm]bool{},
						"gitlab.mine/kl/repo-2":  map[authz.Perm]bool{},
						"gitlab.mine/kl/repo-3":  map[authz.Perm]bool{},
						"gitlab.mine/org/repo-1": map[authz.Perm]bool{authz.Read: true},
						"gitlab.mine/org/repo-2": map[authz.Perm]bool{authz.Read: true},
						"gitlab.mine/org/repo-3": map[authz.Perm]bool{authz.Read: true},
						"gitlab.mine/bl/a":       map[authz.Perm]bool{authz.Read: true},
					},
				},
			},
		},
		// TODO
	}
	for _, test := range tests {
		test.run(t)
	}
}

type GitLab_RepoPerms_Test struct {
	description string

	op GitLabAuthzProviderOp

	calls []GitLab_RepoPerms_call
}

type GitLab_RepoPerms_call struct {
	description string
	account     *extsvc.ExternalAccount
	repos       map[authz.Repo]struct{}
	expPerms    map[api.RepoURI]map[authz.Perm]bool
}

func (g GitLab_RepoPerms_Test) run(t *testing.T) {
	t.Logf("Test case %q", g.description)

	for _, c := range g.calls {
		t.Logf("Call %q", c.description)

		// Recreate the authz provider cache every time, before running twice (once uncached, once cached)
		ctx := context.Background()
		op := g.op
		op.MockCache = make(mockCache)
		authzProvider := NewGitLabAuthzProvider(op)

		for i := 0; i < 2; i++ {
			t.Logf("iter %d", i)
			perms, err := authzProvider.RepoPerms(ctx, c.account, c.repos)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				continue
			}
			if !reflect.DeepEqual(perms, c.expPerms) {
				t.Errorf("expected %+v, but got %+v", c.expPerms, perms)
			}
		}
	}
}

func Test_GitLab_RepoPerms_cache(t *testing.T) {
	gitlabMock := mockGitLab{
		acls: map[string][]string{
			"bl": []string{"bl/repo-1", "bl/repo-2", "bl/repo-3", "org/repo-1", "org/repo-2", "org/repo-3"},
			"kl": []string{"kl/repo-1", "kl/repo-2", "kl/repo-3"},
		},
		projs: map[string]*gitlab.Project{
			"bl/repo-1":  &gitlab.Project{ProjectCommon: gitlab.ProjectCommon{PathWithNamespace: "bl/repo-1"}},
			"bl/repo-2":  &gitlab.Project{ProjectCommon: gitlab.ProjectCommon{PathWithNamespace: "bl/repo-2"}},
			"bl/repo-3":  &gitlab.Project{ProjectCommon: gitlab.ProjectCommon{PathWithNamespace: "bl/repo-3"}},
			"kl/repo-1":  &gitlab.Project{ProjectCommon: gitlab.ProjectCommon{PathWithNamespace: "kl/repo-1"}},
			"kl/repo-2":  &gitlab.Project{ProjectCommon: gitlab.ProjectCommon{PathWithNamespace: "kl/repo-2"}},
			"kl/repo-3":  &gitlab.Project{ProjectCommon: gitlab.ProjectCommon{PathWithNamespace: "kl/repo-3"}},
			"org/repo-1": &gitlab.Project{ProjectCommon: gitlab.ProjectCommon{PathWithNamespace: "org/repo-1"}},
			"org/repo-2": &gitlab.Project{ProjectCommon: gitlab.ProjectCommon{PathWithNamespace: "org/repo-2"}},
			"org/repo-3": &gitlab.Project{ProjectCommon: gitlab.ProjectCommon{PathWithNamespace: "org/repo-3"}},
		},
		t:          t,
		maxPerPage: 100,
	}
	gitlab.MockListProjects = gitlabMock.ListProjects

	ctx := context.Background()
	authzProvider := NewGitLabAuthzProvider(GitLabAuthzProviderOp{
		BaseURL:       mustURL(t, "https://gitlab.mine"),
		AuthnConfigID: auth.ProviderConfigID{ID: "https://gitlab.mine/", Type: gitlab.GitLabServiceType},
		MockCache:     make(mockCache),
	})
	if _, err := authzProvider.RepoPerms(ctx, acct(1, gitlab.GitLabServiceType, "https://gitlab.mine/", "bl"), nil); err != nil {
		t.Fatal(err)
	}
	if exp := map[string]int{"projects?per_page=100&sudo=bl": 1}; !reflect.DeepEqual(gitlabMock.madeProjectReqs, exp) {
		t.Errorf("Unexpected cache behavior. Expected underying requests to be %v, but got %v", exp, gitlabMock.madeProjectReqs)
	}

	if _, err := authzProvider.RepoPerms(ctx, acct(1, gitlab.GitLabServiceType, "https://gitlab.mine/", "bl"), nil); err != nil {
		t.Fatal(err)
	}
	if exp := map[string]int{"projects?per_page=100&sudo=bl": 1}; !reflect.DeepEqual(gitlabMock.madeProjectReqs, exp) {
		t.Errorf("Unexpected cache behavior. Expected underying requests to be %v, but got %v", exp, gitlabMock.madeProjectReqs)
	}

	if _, err := authzProvider.RepoPerms(ctx, acct(1, gitlab.GitLabServiceType, "https://gitlab.mine/", "kl"), nil); err != nil {
		t.Fatal(err)
	}
	if exp := map[string]int{"projects?per_page=100&sudo=bl": 1, "projects?per_page=100&sudo=kl": 1}; !reflect.DeepEqual(gitlabMock.madeProjectReqs, exp) {
		t.Errorf("Unexpected cache behavior. Expected underying requests to be %v, but got %v", exp, gitlabMock.madeProjectReqs)
	}

	if _, err := authzProvider.RepoPerms(ctx, acct(1, gitlab.GitLabServiceType, "https://gitlab.mine/", "kl"), nil); err != nil {
		t.Fatal(err)
	}
	if exp := map[string]int{"projects?per_page=100&sudo=bl": 1, "projects?per_page=100&sudo=kl": 1}; !reflect.DeepEqual(gitlabMock.madeProjectReqs, exp) {
		t.Errorf("Unexpected cache behavior. Expected underying requests to be %v, but got %v", exp, gitlabMock.madeProjectReqs)
	}
}

func Test_GitLab_Repos(t *testing.T) {
	tests := []GitLab_Repos_Test{
		{
			description: "with match pattern",
			op: GitLabAuthzProviderOp{
				BaseURL:      mustURL(t, "https://gitlab.mine"),
				MatchPattern: "gitlab.mine/*",
			},
			calls: []GitLab_Repos_call{
				{
					repos: map[authz.Repo]struct{}{
						authz.Repo{URI: "gitlab.mine/bl/repo-1"}:  struct{}{},
						authz.Repo{URI: "gitlab.mine/kl/repo-1"}:  struct{}{},
						authz.Repo{URI: "another.host/bl/repo-1"}: struct{}{},
						authz.Repo{URI: "a", ExternalRepoSpec: api.ExternalRepoSpec{ServiceType: "gitlab", ServiceID: "https://gitlab.mine/"}}: struct{}{},
					},
					expMine: map[authz.Repo]struct{}{
						authz.Repo{URI: "gitlab.mine/bl/repo-1"}: struct{}{},
						authz.Repo{URI: "gitlab.mine/kl/repo-1"}: struct{}{},
					},
					expOthers: map[authz.Repo]struct{}{
						authz.Repo{URI: "another.host/bl/repo-1"}: struct{}{},
						authz.Repo{URI: "a", ExternalRepoSpec: api.ExternalRepoSpec{ServiceType: "gitlab", ServiceID: "https://gitlab.mine/"}}: struct{}{},
					},
				},
			},
		},
		{
			description: "without match pattern",
			op: GitLabAuthzProviderOp{
				BaseURL: mustURL(t, "https://gitlab.mine"),
			},
			calls: []GitLab_Repos_call{
				{
					repos: map[authz.Repo]struct{}{
						authz.Repo{URI: "gitlab.mine/bl/repo-1"}:  struct{}{},
						authz.Repo{URI: "gitlab.mine/kl/repo-1"}:  struct{}{},
						authz.Repo{URI: "another.host/bl/repo-1"}: struct{}{},
						authz.Repo{URI: "a", ExternalRepoSpec: api.ExternalRepoSpec{
							ServiceType: "gitlab",
							ServiceID:   "https://gitlab.mine/",
						}}: struct{}{},
						authz.Repo{URI: "b", ExternalRepoSpec: api.ExternalRepoSpec{
							ServiceType: "gitlab",
							ServiceID:   "https://not-mine/",
						}}: struct{}{},
						authz.Repo{URI: "c", ExternalRepoSpec: api.ExternalRepoSpec{
							ServiceType: "not-gitlab",
							ServiceID:   "https://gitlab.mine/",
						}}: struct{}{},
					},
					expMine: map[authz.Repo]struct{}{
						authz.Repo{URI: "a", ExternalRepoSpec: api.ExternalRepoSpec{
							ServiceType: "gitlab",
							ServiceID:   "https://gitlab.mine/",
						}}: struct{}{},
					},
					expOthers: map[authz.Repo]struct{}{
						authz.Repo{URI: "gitlab.mine/bl/repo-1"}:  struct{}{},
						authz.Repo{URI: "gitlab.mine/kl/repo-1"}:  struct{}{},
						authz.Repo{URI: "another.host/bl/repo-1"}: struct{}{},
						authz.Repo{URI: "b", ExternalRepoSpec: api.ExternalRepoSpec{
							ServiceType: "gitlab",
							ServiceID:   "https://not-mine/",
						}}: struct{}{},
						authz.Repo{URI: "c", ExternalRepoSpec: api.ExternalRepoSpec{
							ServiceType: "not-gitlab",
							ServiceID:   "https://gitlab.mine/",
						}}: struct{}{},
					},
				},
			},
		},
	}
	for _, test := range tests {
		test.run(t)
	}
}

type GitLab_Repos_Test struct {
	description string
	op          GitLabAuthzProviderOp
	calls       []GitLab_Repos_call
}

type GitLab_Repos_call struct {
	repos     map[authz.Repo]struct{}
	expMine   map[authz.Repo]struct{}
	expOthers map[authz.Repo]struct{}
}

func (g GitLab_Repos_Test) run(t *testing.T) {
	t.Logf("Test case %q", g.description)
	for _, c := range g.calls {
		ctx := context.Background()
		op := g.op
		op.MockCache = make(mockCache)
		authzProvider := NewGitLabAuthzProvider(op)

		mine, others := authzProvider.Repos(ctx, c.repos)
		if !reflect.DeepEqual(mine, c.expMine) {
			t.Errorf("For input %v, expected mine to be %v, but got %v", c.repos, c.expMine, mine)
		}
		if !reflect.DeepEqual(others, c.expOthers) {
			t.Errorf("For input %v, expected others to be %v, but got %v", c.repos, c.expOthers, others)
		}
	}
}

/*
// TODO: discard this in favor of the more componentized tests above
func Test_GitLab_RepoPerms(t *testing.T) {
	tests := []struct {
		description    string
		authnProviders []Provider
		gitlabURL      string
		configID       auth.ProviderConfigID
		gitlabProvider string
		matchPattern   string
		user           *types.User
		accounts       []*extsvc.ExternalAccount
		repos          map[authz.Repo]struct{}
		expPerms       map[api.RepoURI]map[authz.P]bool
	}{{
		description:    "matchPattern enforces bl's perms (short input list)",
		authnProviders: nil,
		gitlabURL:      "https://gitlab.mine/",
		configID:       auth.ProviderConfigID{ID: "https://gitlab.mine/", Type: "gitlab"},
		gitlabProvider: "gitlab",
		matchPattern:   "gitlab.mine/*",
		accounts:       []*extsvc.ExternalAccount{acct(1, "gitlab", "https://gitlab.mine/", "bl")},
		repos: map[authz.Repo]struct{}{
			authz.Repo{URI: "gitlab.mine/bl/repo-1"}:  struct{}{},
			authz.Repo{URI: "gitlab.mine/kl/repo-1"}:  struct{}{},
			authz.Repo{URI: "gitlab.mine/org/repo-1"}: struct{}{},
			authz.Repo{URI: "a", ExternalRepoSpec: api.ExternalRepoSpec{
				ServiceType: "gitlab",
				ServiceID:   "https://gitlab.mine/",
			}}: struct{}{},
		},
		expPerms: map[api.RepoURI]map[authz.P]bool{
			"gitlab.mine/bl/repo-1":  map[authz.P]bool{authz.Read: true},
			"gitlab.mine/kl/repo-1":  map[authz.P]bool{},
			"gitlab.mine/org/repo-1": map[authz.P]bool{authz.Read: true},
		},
		// }, {
		// 	description:  "matchPattern enforces kl's perms (short input list)",
		// 	gitlabURL:    "https://gitlab.mine",
		// 	serviceType:  "gitlab",
		// 	serviceID:    "https://gitlab.mine",
		// 	matchPattern: "gitlab.mine/*",
		// 	accounts:     []*extsvc.ExternalAccount{acct(2, "gitlab", "https://gitlab.mine/", "kl")},
		// 	repos: map[authz.Repo]struct{}{
		// 		authz.Repo{URI: "gitlab.mine/bl/repo-1"}:  struct{}{},
		// 		authz.Repo{URI: "gitlab.mine/kl/repo-1"}:  struct{}{},
		// 		authz.Repo{URI: "gitlab.mine/org/repo-1"}: struct{}{},
		// 		authz.Repo{URI: "a", ExternalRepoSpec: api.ExternalRepoSpec{
		// 			ServiceType: "gitlab",
		// 			ServiceID:   "https://gitlab.mine/",
		// 		}}: struct{}{},
		// 	},
		// 	expPerms: map[api.RepoURI]map[authz.P]bool{
		// 		"gitlab.mine/bl/repo-1":  map[authz.P]bool{},
		// 		"gitlab.mine/kl/repo-1":  map[authz.P]bool{authz.Read: true},
		// 		"gitlab.mine/org/repo-1": map[authz.P]bool{},
		// 	},
		// }, {
		// 	description:  "matchPattern enforces bl's perms (long input list)",
		// 	gitlabURL:    "https://gitlab.mine",
		// 	serviceType:  "gitlab",
		// 	serviceID:    "https://gitlab.mine",
		// 	matchPattern: "gitlab.mine/*",
		// 	accounts:     []*extsvc.ExternalAccount{acct(1, "gitlab", "https://gitlab.mine/", "bl")},
		// 	repos: map[authz.Repo]struct{}{
		// 		authz.Repo{URI: "gitlab.mine/bl/repo-1"}: struct{}{},
		// 		authz.Repo{URI: "gitlab.mine/bl/repo-2"}: struct{}{},
		// 		authz.Repo{URI: "gitlab.mine/bl/repo-3"}: struct{}{},
		// 		authz.Repo{URI: "gitlab.mine/kl/repo-1"}: struct{}{},
		// 		authz.Repo{URI: "gitlab.mine/kl/repo-2"}: struct{}{},
		// 		authz.Repo{URI: "gitlab.mine/kl/repo-3"}: struct{}{},
		// 		authz.Repo{URI: "a", ExternalRepoSpec: api.ExternalRepoSpec{
		// 			ServiceType: "gitlab",
		// 			ServiceID:   "https://gitlab.mine/",
		// 		}}: struct{}{},
		// 	},
		// 	expPerms: map[api.RepoURI]map[authz.P]bool{
		// 		"gitlab.mine/bl/repo-1": map[authz.P]bool{authz.Read: true},
		// 		"gitlab.mine/bl/repo-2": map[authz.P]bool{authz.Read: true},
		// 		"gitlab.mine/bl/repo-3": map[authz.P]bool{authz.Read: true},
		// 		"gitlab.mine/kl/repo-1": map[authz.P]bool{},
		// 		"gitlab.mine/kl/repo-2": map[authz.P]bool{},
		// 		"gitlab.mine/kl/repo-3": map[authz.P]bool{},
		// 	},
		// }, {
		// 	description:  "no matchPattern, use external repo spec",
		// 	gitlabURL:    "https://gitlab.mine",
		// 	serviceType:  "gitlab",
		// 	serviceID:    "https://gitlab.mine",
		// 	matchPattern: "",
		// 	accounts:     []*extsvc.ExternalAccount{acct(1, "gitlab", "https://gitlab.mine/", "bl")},
		// 	repos: map[authz.Repo]struct{}{
		// 		authz.Repo{URI: "gitlab.mine/bl/repo-1"}: struct{}{},
		// 		authz.Repo{URI: "gitlab.mine/bl/repo-2"}: struct{}{},
		// 		authz.Repo{URI: "gitlab.mine/bl/repo-3"}: struct{}{},
		// 		authz.Repo{URI: "gitlab.mine/kl/repo-1"}: struct{}{},
		// 		authz.Repo{URI: "gitlab.mine/kl/repo-2"}: struct{}{},
		// 		authz.Repo{URI: "gitlab.mine/kl/repo-3"}: struct{}{},
		// 		authz.Repo{URI: "gitlab.mine/bl/a", ExternalRepoSpec: api.ExternalRepoSpec{
		// 			ServiceType: "gitlab",
		// 			ServiceID:   "https://gitlab.mine/",
		// 		}}: struct{}{},
		// 		authz.Repo{URI: "gitlab.mine/a", ExternalRepoSpec: api.ExternalRepoSpec{
		// 			ServiceType: "gitlab",
		// 			ServiceID:   "https://gitlab.mine/",
		// 		}}: struct{}{},
		// 		authz.Repo{URI: "a", ExternalRepoSpec: api.ExternalRepoSpec{
		// 			ServiceType: "gitlab",
		// 			ServiceID:   "https://gitlab.mine/",
		// 		}}: struct{}{},
		// 		authz.Repo{URI: "b", ExternalRepoSpec: api.ExternalRepoSpec{
		// 			ServiceType: "gitlab",
		// 			ServiceID:   "https://not-mine/",
		// 		}}: struct{}{},
		// 		authz.Repo{URI: "c", ExternalRepoSpec: api.ExternalRepoSpec{
		// 			ServiceType: "not-gitlab",
		// 			ServiceID:   "https://gitlab.mine/",
		// 		}}: struct{}{},
		// 	},
		// 	expPerms: map[api.RepoURI]map[authz.P]bool{
		// 		"gitlab.mine/bl/a": map[authz.P]bool{authz.Read: true},
		// 		"gitlab.mine/a":    map[authz.P]bool{},
		// 		"a":                map[authz.P]bool{},
		// 	},
		// }, {
		// 	description:  "matchPattern should take precendence over external repo spec",
		// 	gitlabURL:    "https://gitlab.mine",
		// 	serviceType:  "gitlab",
		// 	serviceID:    "https://gitlab.mine",
		// 	matchPattern: "gitlab.mine/*",
		// 	accounts:     []*extsvc.ExternalAccount{acct(1, "gitlab", "https://gitlab.mine/", "bl")},
		// 	repos: map[authz.Repo]struct{}{
		// 		authz.Repo{URI: "gitlab.mine/bl/repo-1"}: struct{}{},
		// 		authz.Repo{URI: "gitlab.mine/bl/repo-2"}: struct{}{},
		// 		authz.Repo{URI: "gitlab.mine/bl/repo-3"}: struct{}{},
		// 		authz.Repo{URI: "gitlab.mine/kl/repo-1"}: struct{}{},
		// 		authz.Repo{URI: "gitlab.mine/kl/repo-2"}: struct{}{},
		// 		authz.Repo{URI: "gitlab.mine/kl/repo-3"}: struct{}{},
		// 		authz.Repo{URI: "gitlab.mine/bl/a", ExternalRepoSpec: api.ExternalRepoSpec{
		// 			ServiceType: "gitlab",
		// 			ServiceID:   "https://gitlab.mine/",
		// 		}}: struct{}{},
		// 		authz.Repo{URI: "gitlab.mine/a", ExternalRepoSpec: api.ExternalRepoSpec{
		// 			ServiceType: "gitlab",
		// 			ServiceID:   "https://gitlab.mine/",
		// 		}}: struct{}{},
		// 		authz.Repo{URI: "a", ExternalRepoSpec: api.ExternalRepoSpec{
		// 			ServiceType: "gitlab",
		// 			ServiceID:   "https://gitlab.mine/",
		// 		}}: struct{}{},
		// 		authz.Repo{URI: "b", ExternalRepoSpec: api.ExternalRepoSpec{
		// 			ServiceType: "gitlab",
		// 			ServiceID:   "https://not-mine/",
		// 		}}: struct{}{},
		// 		authz.Repo{URI: "c", ExternalRepoSpec: api.ExternalRepoSpec{
		// 			ServiceType: "not-gitlab",
		// 			ServiceID:   "https://gitlab.mine/",
		// 		}}: struct{}{},
		// 	},
		// 	expPerms: map[api.RepoURI]map[authz.P]bool{
		// 		"gitlab.mine/bl/repo-1": map[authz.P]bool{authz.Read: true},
		// 		"gitlab.mine/bl/repo-2": map[authz.P]bool{authz.Read: true},
		// 		"gitlab.mine/bl/repo-3": map[authz.P]bool{authz.Read: true},
		// 		"gitlab.mine/bl/a":      map[authz.P]bool{authz.Read: true},
		// 		"gitlab.mine/kl/repo-1": map[authz.P]bool{},
		// 		"gitlab.mine/kl/repo-2": map[authz.P]bool{},
		// 		"gitlab.mine/kl/repo-3": map[authz.P]bool{},
		// 		"gitlab.mine/a":         map[authz.P]bool{},
		// 	},
	}}

	// TODO: test case that exercises FetchAccount path

	gitlabMock := mockGitLab{
		acls: map[authz.AuthzID][]string{
			"bl": []string{"bl/repo-1", "bl/repo-2", "bl/repo-3", "org/repo-1", "org/repo-2", "org/repo-3", "bl/a"},
			"kl": []string{"kl/repo-1", "kl/repo-2", "kl/repo-3"},
		},
		projs: map[string]*gitlab.Project{
			"bl/repo-1":  &gitlab.Project{ProjectCommon: gitlab.ProjectCommon{PathWithNamespace: "bl/repo-1"}},
			"bl/repo-2":  &gitlab.Project{ProjectCommon: gitlab.ProjectCommon{PathWithNamespace: "bl/repo-2"}},
			"bl/repo-3":  &gitlab.Project{ProjectCommon: gitlab.ProjectCommon{PathWithNamespace: "bl/repo-3"}},
			"kl/repo-1":  &gitlab.Project{ProjectCommon: gitlab.ProjectCommon{PathWithNamespace: "kl/repo-1"}},
			"kl/repo-2":  &gitlab.Project{ProjectCommon: gitlab.ProjectCommon{PathWithNamespace: "kl/repo-2"}},
			"kl/repo-3":  &gitlab.Project{ProjectCommon: gitlab.ProjectCommon{PathWithNamespace: "kl/repo-3"}},
			"org/repo-1": &gitlab.Project{ProjectCommon: gitlab.ProjectCommon{PathWithNamespace: "org/repo-1"}},
			"org/repo-2": &gitlab.Project{ProjectCommon: gitlab.ProjectCommon{PathWithNamespace: "org/repo-2"}},
			"org/repo-3": &gitlab.Project{ProjectCommon: gitlab.ProjectCommon{PathWithNamespace: "org/repo-3"}},
			"bl/a":       &gitlab.Project{ProjectCommon: gitlab.ProjectCommon{PathWithNamespace: "bl/a"}},
		},
		t:          t,
		maxPerPage: 1,
	}
	gitlab.MockListProjects = gitlabMock.ListProjects

	for _, test := range tests {
		t.Logf("Test case %q", test.description)
		glURL, err := url.Parse(test.gitlabURL)
		if err != nil {
			t.Fatal(err)
		}

		auth.UpdateProviders(test.authnProviders)

		// Create a new authz provider every time, so the cache is clear
		ctx := context.Background()
		authzProvider := NewGitLabAuthzProvider(GitLabAuthzProviderOp{
			BaseURL: glURL,
			// IdentityServiceID:        test.serviceID,
			// IdentityServiceType:      test.serviceType,
			AuthnConfigID:     test.configID,
			GitLabProvider:    test.gitlabProvider,
			SudoToken:         "",
			RepoPathPattern:   "",
			MatchPattern:      test.matchPattern,
			CacheTTL:          24 * time.Hour,
			MockCache:         make(mockCache),
			UseNativeUsername: false,
		})

		acct, _, err := authzProvider.FetchAccount(ctx, test.user, test.accounts)
		if err != nil {
			t.Fatal(err)
		}

		perms, err := authzProvider.RepoPerms(ctx, acct, test.repos)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(perms, test.expPerms) {
			t.Errorf("Expected perms %+v, but got %+v", test.expPerms, perms)
		}
	}
}
*/

// mockGitLab is a mock for the GitLab client that can be used by tests. Instantiating a mockGitLab
// instance itself does nothing, but its methods can be used to replace the mock functions (e.g.,
// MockListProjects).
//
// We prefer to do it this way, instead of defining an interface for the GitLab client, because this
// preserves the ability to jump-to-def around the actual implementation.
type mockGitLab struct {
	t *testing.T

	// acls is a map from GitLab user id to list of accessible repository paths on GitLab
	acls       map[string][]string
	projs      map[string]*gitlab.Project
	users      []*gitlab.User
	maxPerPage int

	madeUserReqs    map[string]int
	madeProjectReqs map[string]int
}

func (m *mockGitLab) ListUsers(ctx context.Context, urlStr string) (users []*gitlab.User, nextPageURL *string, err error) {
	if m.madeUserReqs == nil {
		m.madeUserReqs = make(map[string]int)
	}
	m.madeUserReqs[urlStr]++

	u, err := url.Parse(urlStr)
	if err != nil {
		m.t.Fatalf("could not parse ListUsers urlStr %q: %s", urlStr, err)
	}

	var matchingUsers []*gitlab.User
	for _, user := range m.users {
		userMatches := true
		if qExternUID := u.Query().Get("extern_uid"); qExternUID != "" {
			qProvider := u.Query().Get("provider")

			match := false
			for _, identity := range user.Identities {
				if identity.ExternUID == qExternUID && identity.Provider == qProvider {
					match = true
					break
				}
			}
			if !match {
				userMatches = false
				break
			}
		}
		if qUsername := u.Query().Get("username"); qUsername != "" {
			if user.Username != qUsername {
				userMatches = false
				break
			}
		}
		if userMatches {
			matchingUsers = append(matchingUsers, user)
		}
	}

	// pagination
	perPage, err := getIntOrDefault(u.Query().Get("per_page"), m.maxPerPage)
	if err != nil {
		return nil, nil, err
	}
	page, err := getIntOrDefault(u.Query().Get("page"), 1)
	if err != nil {
		return nil, nil, err
	}
	p := page - 1
	var (
		pagedUsers []*gitlab.User
	)
	if perPage*p > len(matchingUsers)-1 {
		pagedUsers = nil
	} else if perPage*(p+1) > len(matchingUsers)-1 {
		pagedUsers = matchingUsers[perPage*p:]
	} else {
		pagedUsers = matchingUsers[perPage*p : perPage*(p+1)]
		if perPage*(p+1) <= len(matchingUsers)-1 {
			newU := *u
			q := u.Query()
			q.Set("page", strconv.Itoa(page+1))
			newU.RawQuery = q.Encode()
			s := newU.String()
			nextPageURL = &s
		}
	}
	return pagedUsers, nextPageURL, nil
}

func (m *mockGitLab) ListProjects(ctx context.Context, urlStr string) (proj []*gitlab.Project, nextPageURL *string, err error) {
	if m.madeProjectReqs == nil {
		m.madeProjectReqs = make(map[string]int)
	}
	m.madeProjectReqs[urlStr]++

	u, err := url.Parse(urlStr)
	if err != nil {
		m.t.Fatalf("could not parse ListProjects urlStr %q: %s", urlStr, err)
	}
	repoNames := m.acls[u.Query().Get("sudo")]
	allProjs := make([]*gitlab.Project, len(repoNames))
	for i, repoName := range repoNames {
		proj, ok := m.projs[repoName]
		if !ok {
			m.t.Fatalf("Dangling project reference in mockGitLab: %s", repoName)
		}
		allProjs[i] = proj
	}

	// pagination
	perPage, err := getIntOrDefault(u.Query().Get("per_page"), m.maxPerPage)
	if err != nil {
		return nil, nil, err
	}
	if perPage > m.maxPerPage {
		perPage = m.maxPerPage
	}
	page, err := getIntOrDefault(u.Query().Get("page"), 1)
	if err != nil {
		return nil, nil, err
	}
	p := page - 1
	var (
		pagedProjs []*gitlab.Project
	)
	if perPage*p > len(allProjs)-1 {
		pagedProjs = nil
	} else if perPage*(p+1) > len(allProjs)-1 {
		pagedProjs = allProjs[perPage*p:]
	} else {
		pagedProjs = allProjs[perPage*p : perPage*(p+1)]
		if perPage*(p+1) <= len(allProjs)-1 {
			newU := *u
			q := u.Query()
			q.Set("page", strconv.Itoa(page+1))
			newU.RawQuery = q.Encode()
			s := newU.String()
			nextPageURL = &s
		}
	}
	return pagedProjs, nextPageURL, nil
}

type mockCache map[string]string

func (m mockCache) Get(key string) ([]byte, bool) {
	v, ok := m[key]
	return []byte(v), ok
}
func (m mockCache) Set(key string, b []byte) {
	m[key] = string(b)
}
func (m mockCache) Delete(key string) {
	delete(m, key)
}

func getIntOrDefault(str string, def int) (int, error) {
	if str == "" {
		return def, nil
	}
	return strconv.Atoi(str)
}

func acct(userID int32, serviceType, serviceID, accountID string) *extsvc.ExternalAccount {
	return &extsvc.ExternalAccount{
		UserID: userID,
		ExternalAccountSpec: extsvc.ExternalAccountSpec{
			ServiceType: serviceType,
			ServiceID:   serviceID,
			AccountID:   accountID,
		},
	}
}

type mockAuthnProvider struct {
	configID  auth.ProviderConfigID
	serviceID string
}

func (m mockAuthnProvider) ConfigID() auth.ProviderConfigID {
	return m.configID
}

func (m mockAuthnProvider) Config() schema.AuthProviders {
	panic("should not be called")
}

func (m mockAuthnProvider) CachedInfo() *auth.ProviderInfo {
	return &auth.ProviderInfo{ServiceID: m.serviceID}
}

func (m mockAuthnProvider) Refresh(ctx context.Context) error {
	panic("should not be called")
}

func mustURL(t *testing.T, u string) *url.URL {
	parsed, err := url.Parse(u)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
