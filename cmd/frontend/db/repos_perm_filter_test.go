package db

import (
	"context"
	"reflect"
	"testing"

	"github.com/sourcegraph/sourcegraph/cmd/frontend/internal/authz"
	"github.com/sourcegraph/sourcegraph/cmd/frontend/types"
	"github.com/sourcegraph/sourcegraph/pkg/actor"
	"github.com/sourcegraph/sourcegraph/pkg/api"
	"github.com/sourcegraph/sourcegraph/pkg/extsvc"
)

// TODO: test for 	expNewUserAccounts []extsvc.ExternalAccountSpec

type authzFilter_Test struct {
	description string

	permsAllowByDefault bool
	authzProviders      []authz.AuthzProvider

	calls []authzFilter_call
}

type authzFilter_call struct {
	description string

	isAuthenticated bool
	userAccounts    []*extsvc.ExternalAccount

	repos []*types.Repo
	perm  authz.Perm

	expFilteredRepos []*types.Repo
}

func (r authzFilter_Test) run(t *testing.T) {
	t.Logf("Test case %q", r.description)

	// No dependence on user data
	Mocks.Users.GetByCurrentAuthUser = func(ctx context.Context) (*types.User, error) {
		return &types.User{}, nil
	}
	authz.SetProviders(r.permsAllowByDefault, r.authzProviders)

	for _, c := range r.calls {
		t.Logf("Call %q", c.description)

		ctx := context.Background()
		if c.isAuthenticated {
			ctx = actor.WithActor(ctx, &actor.Actor{UID: 1})
		}

		Mocks.ExternalAccounts.AssociateUserAndSave = func(userID int32, spec extsvc.ExternalAccountSpec, data extsvc.ExternalAccountData) error { return nil }
		Mocks.ExternalAccounts.List = func(ExternalAccountsListOptions) ([]*extsvc.ExternalAccount, error) { return c.userAccounts, nil }

		filteredRepos, err := authzFilter(ctx, c.repos, c.perm)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(filteredRepos, c.expFilteredRepos) {
			a := make([]api.RepoURI, len(filteredRepos))
			for i, v := range filteredRepos {
				a[i] = v.URI
			}
			e := make([]api.RepoURI, len(c.expFilteredRepos))
			for i, v := range c.expFilteredRepos {
				e[i] = v.URI
			}
			t.Errorf("Expected filtered repos\n\t%v\n, but got\n\t%v", e, a)
		}
	}
}

func Test_authzFilter2(t *testing.T) {
	tests := []authzFilter_Test{
		{
			description: "1 authz provider, ext account exists",

			permsAllowByDefault: true,
			authzProviders: []authz.AuthzProvider{
				&MockAuthzProvider{
					serviceID:   "https://gitlab.mine/",
					serviceType: "gitlab",
					repos: map[api.RepoURI]struct{}{
						"gitlab.mine/u1/r0":            struct{}{},
						"gitlab.mine/u2/r0":            struct{}{},
						"gitlab.mine/sharedPrivate/r0": struct{}{},
						"gitlab.mine/public/r0":        struct{}{},
					},
					perms: map[extsvc.ExternalAccount]map[api.RepoURI]map[authz.Perm]bool{
						*acct(1, "gitlab", "https://gitlab.mine/", "u1"): map[api.RepoURI]map[authz.Perm]bool{
							"gitlab.mine/u1/r0":            map[authz.Perm]bool{authz.Read: true},
							"gitlab.mine/u2/r0":            map[authz.Perm]bool{},
							"gitlab.mine/sharedPrivate/r0": map[authz.Perm]bool{authz.Read: true},
							"gitlab.mine/public/r0":        map[authz.Perm]bool{authz.Read: true},
						},
						*acct(2, "gitlab", "https://gitlab.mine/", "u2"): map[api.RepoURI]map[authz.Perm]bool{
							"gitlab.mine/u1/r0":            map[authz.Perm]bool{},
							"gitlab.mine/u2/r0":            map[authz.Perm]bool{authz.Read: true},
							"gitlab.mine/sharedPrivate/r0": map[authz.Perm]bool{authz.Read: true},
							"gitlab.mine/public/r0":        map[authz.Perm]bool{authz.Read: true},
						},
						extsvc.ExternalAccount{}: map[api.RepoURI]map[authz.Perm]bool{
							"gitlab.mine/u1/r0":            map[authz.Perm]bool{},
							"gitlab.mine/u2/r0":            map[authz.Perm]bool{},
							"gitlab.mine/sharedPrivate/r0": map[authz.Perm]bool{},
							"gitlab.mine/public/r0":        map[authz.Perm]bool{authz.Read: true},
						},
					},
				},
			},
			calls: []authzFilter_call{
				{
					description:     "u1 can read its own repo",
					isAuthenticated: true,
					userAccounts:    []*extsvc.ExternalAccount{acct(1, "gitlab", "https://gitlab.mine/", "u1")},
					repos: []*types.Repo{
						{URI: "gitlab.mine/u1/r0"},
					},
					perm: authz.Read,
					expFilteredRepos: []*types.Repo{
						{URI: "gitlab.mine/u1/r0"},
					},
				},
				{
					description:     "u1 not allowed to read u2's repo",
					isAuthenticated: true,
					userAccounts:    []*extsvc.ExternalAccount{acct(1, "gitlab", "https://gitlab.mine/", "u1")},
					repos: []*types.Repo{
						{URI: "gitlab.mine/u1/r0"},
						{URI: "gitlab.mine/u2/r0"},
						{URI: "gitlab.mine/sharedPrivate/r0"},
						{URI: "gitlab.mine/public/r0"},
					},
					perm: authz.Read,
					expFilteredRepos: []*types.Repo{
						{URI: "gitlab.mine/u1/r0"},
						{URI: "gitlab.mine/sharedPrivate/r0"},
						{URI: "gitlab.mine/public/r0"},
					},
				},
				{
					description:     "u2 not allowed to read u0's repo",
					isAuthenticated: true,
					userAccounts:    []*extsvc.ExternalAccount{acct(2, "gitlab", "https://gitlab.mine/", "u2")},
					repos: []*types.Repo{
						{URI: "gitlab.mine/u1/r0"},
						{URI: "gitlab.mine/u2/r0"},
						{URI: "gitlab.mine/sharedPrivate/r0"},
						{URI: "gitlab.mine/public/r0"},
					},
					perm: authz.Read,
					expFilteredRepos: []*types.Repo{
						{URI: "gitlab.mine/u2/r0"},
						{URI: "gitlab.mine/sharedPrivate/r0"},
						{URI: "gitlab.mine/public/r0"},
					},
				}, {
					description:     "u99 not allowed to read anyone's repo",
					isAuthenticated: true,
					userAccounts:    []*extsvc.ExternalAccount{acct(99, "gitlab", "https://gitlab.mine/", "u99")},
					repos: []*types.Repo{
						{URI: "gitlab.mine/u1/r0"},
						{URI: "gitlab.mine/u2/r0"},
						{URI: "gitlab.mine/sharedPrivate/r0"},
						{URI: "gitlab.mine/public/r0"},
					},
					expFilteredRepos: []*types.Repo{
						{URI: "gitlab.mine/public/r0"},
					},
					perm: authz.Read,
				}, {
					description:     "u99 can read unmanaged repo",
					isAuthenticated: true,
					userAccounts:    []*extsvc.ExternalAccount{acct(99, "gitlab", "https://gitlab.mine/", "u99")},
					repos: []*types.Repo{
						{URI: "other.mine/r"},
					},
					expFilteredRepos: []*types.Repo{
						{URI: "other.mine/r"},
					},
					perm: authz.Read,
				}, {
					description:     "u1 can read its own, public, and unmanaged repos",
					isAuthenticated: true,
					userAccounts:    []*extsvc.ExternalAccount{acct(1, "gitlab", "https://gitlab.mine/", "u1")},
					repos: []*types.Repo{
						{URI: "gitlab.mine/u1/r0"},
						{URI: "gitlab.mine/u2/r0"},
						{URI: "gitlab.mine/sharedPrivate/r0"},
						{URI: "gitlab.mine/public/r0"},
						{URI: "otherHost/r0"},
					},
					expFilteredRepos: []*types.Repo{
						{URI: "gitlab.mine/u1/r0"},
						{URI: "gitlab.mine/sharedPrivate/r0"},
						{URI: "gitlab.mine/public/r0"},
						{URI: "otherHost/r0"},
					},
					perm: authz.Read,
				}, {
					description:     "authenticated but 0 accounts can read public anad unmanaged repos",
					isAuthenticated: true,
					userAccounts:    nil,
					repos: []*types.Repo{
						{URI: "gitlab.mine/u1/r0"},
						{URI: "gitlab.mine/u2/r0"},
						{URI: "gitlab.mine/sharedPrivate/r0"},
						{URI: "gitlab.mine/public/r0"},
						{URI: "otherHost/r0"},
					},
					expFilteredRepos: []*types.Repo{
						{URI: "gitlab.mine/public/r0"},
						{URI: "otherHost/r0"},
					},
					perm: authz.Read,
				}, {
					description:     "unauthenticated can read public and unmanaged repos",
					isAuthenticated: false,
					userAccounts:    nil,
					repos: []*types.Repo{
						{URI: "gitlab.mine/u1/r0"},
						{URI: "gitlab.mine/u2/r0"},
						{URI: "gitlab.mine/sharedPrivate/r0"},
						{URI: "gitlab.mine/public/r0"},
						{URI: "otherHost/r0"},
					},
					expFilteredRepos: []*types.Repo{
						{URI: "gitlab.mine/public/r0"},
						{URI: "otherHost/r0"},
					},
					perm: authz.Read,
				},
			},
		},
		// TODO
	}
	for _, test := range tests {
		test.run(t)
	}
}

func Test_authzFilter(t *testing.T) {
	type queryTestCase struct {
		description        string
		isAuthenticated    bool
		userAccounts       []*extsvc.ExternalAccount
		repos              []*types.Repo
		perm               authz.Perm
		expFilteredRepos   []*types.Repo
		expNewUserAccounts []extsvc.ExternalAccountSpec
	}
	tests := []struct {
		description         string
		permsAllowByDefault bool
		authzProviders      []authz.AuthzProvider
		queries             []queryTestCase
	}{{
		description:         "1 authz provider, ext account exists",
		permsAllowByDefault: true,
		authzProviders: []authz.AuthzProvider{
			&MockAuthzProvider{
				serviceID:   "https://gitlab.mine/",
				serviceType: "gitlab",
				repos: map[api.RepoURI]struct{}{
					"gitlab.mine/u1/r0":            struct{}{},
					"gitlab.mine/u2/r0":            struct{}{},
					"gitlab.mine/sharedPrivate/r0": struct{}{},
					"gitlab.mine/public/r0":        struct{}{},
				},
				perms: map[extsvc.ExternalAccount]map[api.RepoURI]map[authz.Perm]bool{
					*acct(1, "gitlab", "https://gitlab.mine/", "u1"): map[api.RepoURI]map[authz.Perm]bool{
						"gitlab.mine/u1/r0":            map[authz.Perm]bool{authz.Read: true},
						"gitlab.mine/u2/r0":            map[authz.Perm]bool{},
						"gitlab.mine/sharedPrivate/r0": map[authz.Perm]bool{authz.Read: true},
						"gitlab.mine/public/r0":        map[authz.Perm]bool{authz.Read: true},
					},
					*acct(2, "gitlab", "https://gitlab.mine/", "u2"): map[api.RepoURI]map[authz.Perm]bool{
						"gitlab.mine/u1/r0":            map[authz.Perm]bool{},
						"gitlab.mine/u2/r0":            map[authz.Perm]bool{authz.Read: true},
						"gitlab.mine/sharedPrivate/r0": map[authz.Perm]bool{authz.Read: true},
						"gitlab.mine/public/r0":        map[authz.Perm]bool{authz.Read: true},
					},
					extsvc.ExternalAccount{}: map[api.RepoURI]map[authz.Perm]bool{
						"gitlab.mine/u1/r0":            map[authz.Perm]bool{},
						"gitlab.mine/u2/r0":            map[authz.Perm]bool{},
						"gitlab.mine/sharedPrivate/r0": map[authz.Perm]bool{},
						"gitlab.mine/public/r0":        map[authz.Perm]bool{authz.Read: true},
					},
				},
			},
		},
		queries: []queryTestCase{
			{
				description:     "u1 can read its own repo",
				isAuthenticated: true,
				userAccounts:    []*extsvc.ExternalAccount{acct(1, "gitlab", "https://gitlab.mine/", "u1")},
				repos: []*types.Repo{
					{URI: "gitlab.mine/u1/r0"},
				},
				expFilteredRepos: []*types.Repo{
					{URI: "gitlab.mine/u1/r0"},
				},
				perm: authz.Read,
			}, {
				description:     "u1 not allowed to read u2's repo",
				isAuthenticated: true,
				userAccounts:    []*extsvc.ExternalAccount{acct(1, "gitlab", "https://gitlab.mine/", "u1")},
				repos: []*types.Repo{
					{URI: "gitlab.mine/u1/r0"},
					{URI: "gitlab.mine/u2/r0"},
					{URI: "gitlab.mine/sharedPrivate/r0"},
					{URI: "gitlab.mine/public/r0"},
				},
				expFilteredRepos: []*types.Repo{
					{URI: "gitlab.mine/u1/r0"},
					{URI: "gitlab.mine/sharedPrivate/r0"},
					{URI: "gitlab.mine/public/r0"},
				},
				perm: authz.Read,
			}, {
				description:     "u2 not allowed to read u0's repo",
				isAuthenticated: true,
				userAccounts:    []*extsvc.ExternalAccount{acct(2, "gitlab", "https://gitlab.mine/", "u2")},
				repos: []*types.Repo{
					{URI: "gitlab.mine/u1/r0"},
					{URI: "gitlab.mine/u2/r0"},
					{URI: "gitlab.mine/sharedPrivate/r0"},
					{URI: "gitlab.mine/public/r0"},
				},
				expFilteredRepos: []*types.Repo{
					{URI: "gitlab.mine/u2/r0"},
					{URI: "gitlab.mine/sharedPrivate/r0"},
					{URI: "gitlab.mine/public/r0"},
				},
				perm: authz.Read,
			}, {
				description:     "u99 not allowed to read anyone's repo",
				isAuthenticated: true,
				userAccounts:    []*extsvc.ExternalAccount{acct(99, "gitlab", "https://gitlab.mine/", "u99")},
				repos: []*types.Repo{
					{URI: "gitlab.mine/u1/r0"},
					{URI: "gitlab.mine/u2/r0"},
					{URI: "gitlab.mine/sharedPrivate/r0"},
					{URI: "gitlab.mine/public/r0"},
				},
				expFilteredRepos: []*types.Repo{
					{URI: "gitlab.mine/public/r0"},
				},
				perm: authz.Read,
			}, {
				description:     "u99 can read unmanaged repo",
				isAuthenticated: true,
				userAccounts:    []*extsvc.ExternalAccount{acct(99, "gitlab", "https://gitlab.mine/", "u99")},
				repos: []*types.Repo{
					{URI: "other.mine/r"},
				},
				expFilteredRepos: []*types.Repo{
					{URI: "other.mine/r"},
				},
				perm: authz.Read,
			}, {
				description:     "u1 can read its own, public, and unmanaged repos",
				isAuthenticated: true,
				userAccounts:    []*extsvc.ExternalAccount{acct(1, "gitlab", "https://gitlab.mine/", "u1")},
				repos: []*types.Repo{
					{URI: "gitlab.mine/u1/r0"},
					{URI: "gitlab.mine/u2/r0"},
					{URI: "gitlab.mine/sharedPrivate/r0"},
					{URI: "gitlab.mine/public/r0"},
					{URI: "otherHost/r0"},
				},
				expFilteredRepos: []*types.Repo{
					{URI: "gitlab.mine/u1/r0"},
					{URI: "gitlab.mine/sharedPrivate/r0"},
					{URI: "gitlab.mine/public/r0"},
					{URI: "otherHost/r0"},
				},
				perm: authz.Read,
			}, {
				description:     "authenticated but 0 accounts can read public anad unmanaged repos",
				isAuthenticated: true,
				userAccounts:    nil,
				repos: []*types.Repo{
					{URI: "gitlab.mine/u1/r0"},
					{URI: "gitlab.mine/u2/r0"},
					{URI: "gitlab.mine/sharedPrivate/r0"},
					{URI: "gitlab.mine/public/r0"},
					{URI: "otherHost/r0"},
				},
				expFilteredRepos: []*types.Repo{
					{URI: "gitlab.mine/public/r0"},
					{URI: "otherHost/r0"},
				},
				perm: authz.Read,
			}, {
				description:     "unauthenticated can read public and unmanaged repos",
				isAuthenticated: false,
				userAccounts:    nil,
				repos: []*types.Repo{
					{URI: "gitlab.mine/u1/r0"},
					{URI: "gitlab.mine/u2/r0"},
					{URI: "gitlab.mine/sharedPrivate/r0"},
					{URI: "gitlab.mine/public/r0"},
					{URI: "otherHost/r0"},
				},
				expFilteredRepos: []*types.Repo{
					{URI: "gitlab.mine/public/r0"},
					{URI: "otherHost/r0"},
				},
				perm: authz.Read,
			},
		},
	}, {
		description:         "2 authz providers, ext accounts exist",
		permsAllowByDefault: true,
		authzProviders: []authz.AuthzProvider{
			&MockAuthzProvider{
				serviceID:   "https://gitlab0.mine/",
				serviceType: "gitlab",
				repos: map[api.RepoURI]struct{}{
					"gitlab0.mine/u1/r0":     struct{}{},
					"gitlab0.mine/u2/r0":     struct{}{},
					"gitlab0.mine/public/r0": struct{}{},
				},
				perms: map[extsvc.ExternalAccount]map[api.RepoURI]map[authz.Perm]bool{
					*acct(1, "gitlab", "https://gitlab0.mine/", "u1"): map[api.RepoURI]map[authz.Perm]bool{
						"gitlab0.mine/u1/r0":     map[authz.Perm]bool{authz.Read: true},
						"gitlab0.mine/u2/r0":     map[authz.Perm]bool{},
						"gitlab0.mine/public/r0": map[authz.Perm]bool{authz.Read: true},
					},
					*acct(2, "gitlab", "https://gitlab0.mine/", "u2"): map[api.RepoURI]map[authz.Perm]bool{
						"gitlab0.mine/u1/r0":     map[authz.Perm]bool{},
						"gitlab0.mine/u2/r0":     map[authz.Perm]bool{authz.Read: true},
						"gitlab0.mine/public/r0": map[authz.Perm]bool{authz.Read: true},
					},
				},
			},
			&MockAuthzProvider{
				serviceID:   "https://gitlab1.mine/",
				serviceType: "gitlab",
				repos: map[api.RepoURI]struct{}{
					"gitlab1.mine/u1/r0":     struct{}{},
					"gitlab1.mine/u2/r0":     struct{}{},
					"gitlab1.mine/public/r0": struct{}{},
				},
				perms: map[extsvc.ExternalAccount]map[api.RepoURI]map[authz.Perm]bool{
					*acct(1, "gitlab", "https://gitlab1.mine/", "u1"): map[api.RepoURI]map[authz.Perm]bool{
						"gitlab1.mine/u1/r0":     map[authz.Perm]bool{authz.Read: true},
						"gitlab1.mine/u2/r0":     map[authz.Perm]bool{},
						"gitlab1.mine/public/r0": map[authz.Perm]bool{authz.Read: true},
					},
					*acct(2, "gitlab", "https://gitlab1.mine/", "u2"): map[api.RepoURI]map[authz.Perm]bool{
						"gitlab1.mine/u1/r0":     map[authz.Perm]bool{},
						"gitlab1.mine/u2/r0":     map[authz.Perm]bool{authz.Read: true},
						"gitlab1.mine/public/r0": map[authz.Perm]bool{authz.Read: true},
					},
				},
			},
		},
		queries: []queryTestCase{
			{
				description:     "u1 can read its own repos, but not others'",
				isAuthenticated: true,
				userAccounts: []*extsvc.ExternalAccount{
					acct(1, "gitlab", "https://gitlab0.mine/", "u1"),
					acct(1, "gitlab", "https://gitlab1.mine/", "u1"),
				},
				repos: []*types.Repo{
					{URI: "gitlab0.mine/u1/r0"},
					{URI: "gitlab0.mine/u2/r0"},
					{URI: "gitlab0.mine/public/r0"},
					{URI: "gitlab1.mine/u1/r0"},
					{URI: "gitlab1.mine/u2/r0"},
					{URI: "gitlab1.mine/public/r0"},
					{URI: "gitlab2.mine/u2/r0"},
					{URI: "otherHost/r0"},
				},
				expFilteredRepos: []*types.Repo{
					{URI: "gitlab0.mine/u1/r0"},
					{URI: "gitlab0.mine/public/r0"},
					{URI: "gitlab1.mine/u1/r0"},
					{URI: "gitlab1.mine/public/r0"},
					{URI: "gitlab2.mine/u2/r0"},
					{URI: "otherHost/r0"},
				},
				perm: authz.Read,
			},
		},
	}, {
		description:         "2 authz providers, ext account exists, permsAllowByDefault=false",
		permsAllowByDefault: false,
		authzProviders: []authz.AuthzProvider{
			&MockAuthzProvider{
				serviceID:   "https://gitlab0.mine/",
				serviceType: "gitlab",
				repos: map[api.RepoURI]struct{}{
					"gitlab0.mine/u1/r0":     struct{}{},
					"gitlab0.mine/u2/r0":     struct{}{},
					"gitlab0.mine/public/r0": struct{}{},
				},
				perms: map[extsvc.ExternalAccount]map[api.RepoURI]map[authz.Perm]bool{
					*acct(1, "gitlab", "https://gitlab0.mine/", "u1"): map[api.RepoURI]map[authz.Perm]bool{
						"gitlab0.mine/u1/r0":     map[authz.Perm]bool{authz.Read: true},
						"gitlab0.mine/u2/r0":     map[authz.Perm]bool{},
						"gitlab0.mine/public/r0": map[authz.Perm]bool{authz.Read: true},
					},
					*acct(2, "gitlab", "https://gitlab0.mine/", "u2"): map[api.RepoURI]map[authz.Perm]bool{
						"gitlab0.mine/u1/r0":     map[authz.Perm]bool{},
						"gitlab0.mine/u2/r0":     map[authz.Perm]bool{authz.Read: true},
						"gitlab0.mine/public/r0": map[authz.Perm]bool{authz.Read: true},
					},
				},
			},
			&MockAuthzProvider{
				serviceID:   "https://gitlab1.mine/",
				serviceType: "gitlab",
				repos: map[api.RepoURI]struct{}{
					"gitlab1.mine/u1/r0":     struct{}{},
					"gitlab1.mine/u2/r0":     struct{}{},
					"gitlab1.mine/public/r0": struct{}{},
				},
				perms: map[extsvc.ExternalAccount]map[api.RepoURI]map[authz.Perm]bool{
					*acct(1, "gitlab", "https://gitlab1.mine/", "u1"): map[api.RepoURI]map[authz.Perm]bool{
						"gitlab1.mine/u1/r0":     map[authz.Perm]bool{authz.Read: true},
						"gitlab1.mine/u2/r0":     map[authz.Perm]bool{},
						"gitlab1.mine/public/r0": map[authz.Perm]bool{authz.Read: true},
					},
					*acct(2, "gitlab", "https://gitlab1.mine/", "u2"): map[api.RepoURI]map[authz.Perm]bool{
						"gitlab1.mine/u1/r0":     map[authz.Perm]bool{},
						"gitlab1.mine/u2/r0":     map[authz.Perm]bool{authz.Read: true},
						"gitlab1.mine/public/r0": map[authz.Perm]bool{authz.Read: true},
					},
				},
			},
		},
		queries: []queryTestCase{
			{
				description:     "u1 can read its own repos, but not others'",
				isAuthenticated: true,
				userAccounts: []*extsvc.ExternalAccount{
					acct(1, "gitlab", "https://gitlab0.mine/", "u1"),
					acct(1, "gitlab", "https://gitlab1.mine/", "u1"),
				},
				repos: []*types.Repo{
					{URI: "gitlab0.mine/u1/r0"},
					{URI: "gitlab0.mine/u2/r0"},
					{URI: "gitlab0.mine/public/r0"},
					{URI: "gitlab1.mine/u1/r0"},
					{URI: "gitlab1.mine/u2/r0"},
					{URI: "gitlab1.mine/public/r0"},
					{URI: "gitlab2.mine/u2/r0"},
					{URI: "otherHost/r0"},
				},
				expFilteredRepos: []*types.Repo{
					{URI: "gitlab0.mine/u1/r0"},
					{URI: "gitlab0.mine/public/r0"},
					{URI: "gitlab1.mine/u1/r0"},
					{URI: "gitlab1.mine/public/r0"},
				},
				perm: authz.Read,
			},
		},
	}, {
		description:         "1 authz provider, ext account doesn't exist",
		permsAllowByDefault: true,
		authzProviders: []authz.AuthzProvider{
			&MockAuthzProvider{
				serviceID:    "https://gitlab.mine/",
				serviceType:  "gitlab",
				okServiceIDs: map[string]struct{}{"https://okta.mine/": struct{}{}},
				repos: map[api.RepoURI]struct{}{
					"gitlab.mine/u1/r0":     struct{}{},
					"gitlab.mine/u2/r0":     struct{}{},
					"gitlab.mine/public/r0": struct{}{},
				},
				perms: map[extsvc.ExternalAccount]map[api.RepoURI]map[authz.Perm]bool{
					*acct(1, "gitlab", "https://gitlab.mine/", "u1"): map[api.RepoURI]map[authz.Perm]bool{
						"gitlab.mine/u1/r0":     map[authz.Perm]bool{authz.Read: true},
						"gitlab.mine/u2/r0":     map[authz.Perm]bool{},
						"gitlab.mine/public/r0": map[authz.Perm]bool{authz.Read: true},
					},
					*acct(2, "gitlab", "https://gitlab.mine/", "u2"): map[api.RepoURI]map[authz.Perm]bool{
						"gitlab.mine/u1/r0":     map[authz.Perm]bool{},
						"gitlab.mine/u2/r0":     map[authz.Perm]bool{authz.Read: true},
						"gitlab.mine/public/r0": map[authz.Perm]bool{authz.Read: true},
					},
					// entry for nil account / anonymous users
					extsvc.ExternalAccount{}: map[api.RepoURI]map[authz.Perm]bool{
						"gitlab.mine/u1/r0":     map[authz.Perm]bool{},
						"gitlab.mine/u2/r0":     map[authz.Perm]bool{},
						"gitlab.mine/public/r0": map[authz.Perm]bool{authz.Read: true},
					},
				},
			},
		},
		queries: []queryTestCase{
			{
				description:     "new ext account should be created",
				isAuthenticated: true,
				userAccounts:    []*extsvc.ExternalAccount{acct(1, "saml", "https://okta.mine/", "u1")},
				repos: []*types.Repo{
					{URI: "gitlab.mine/u1/r0"},
					{URI: "gitlab.mine/u2/r0"},
					{URI: "gitlab.mine/public/r0"},
				},
				perm: authz.Read,
				expFilteredRepos: []*types.Repo{
					{URI: "gitlab.mine/u1/r0"},
					{URI: "gitlab.mine/public/r0"},
				},
				expNewUserAccounts: []extsvc.ExternalAccountSpec{{
					ServiceType: "gitlab",
					ServiceID:   "https://gitlab.mine/",
					AccountID:   "u1",
				}},
			},
			{
				description:     "new ext account should not be created for user that doesn't exist",
				isAuthenticated: true,
				userAccounts:    []*extsvc.ExternalAccount{acct(1, "saml", "https://okta.mine/", "u99")},
				repos: []*types.Repo{
					{URI: "gitlab.mine/u1/r0"},
					{URI: "gitlab.mine/u2/r0"},
					{URI: "gitlab.mine/public/r0"},
				},
				expFilteredRepos: []*types.Repo{
					{URI: "gitlab.mine/public/r0"},
				},
				perm: authz.Read,
			},
			{
				description:     "new ext account should not be created when service ID not ok",
				isAuthenticated: true,
				userAccounts:    []*extsvc.ExternalAccount{acct(1, "saml", "https://rando.mine/", "u1")},
				repos: []*types.Repo{
					{URI: "gitlab.mine/u1/r0"},
					{URI: "gitlab.mine/u2/r0"},
					{URI: "gitlab.mine/public/r0"},
				},
				expFilteredRepos: []*types.Repo{
					{URI: "gitlab.mine/public/r0"},
				},
				perm: authz.Read,
			},
			{
				description:     "unauthenticated user",
				isAuthenticated: false,
				userAccounts:    nil,
				repos: []*types.Repo{
					{URI: "gitlab.mine/u1/r0"},
					{URI: "gitlab.mine/u2/r0"},
					{URI: "gitlab.mine/public/r0"},
				},
				expFilteredRepos: []*types.Repo{
					{URI: "gitlab.mine/public/r0"},
				},
				perm: authz.Read,
			},
		},
	}}

	// No dependence on user data
	Mocks.Users.GetByCurrentAuthUser = func(ctx context.Context) (*types.User, error) {
		return &types.User{}, nil
	}

	for _, test := range tests {
		t.Logf("Running test %q", test.description)
		authz.SetProviders(test.permsAllowByDefault, test.authzProviders)
		for _, q := range test.queries {
			t.Logf("Running query %q", q.description)

			ctx := context.Background()
			if q.isAuthenticated {
				ctx = actor.WithActor(ctx, &actor.Actor{UID: 1})
			}

			var newUserAccounts []extsvc.ExternalAccountSpec
			Mocks.ExternalAccounts.AssociateUserAndSave = func(userID int32, spec extsvc.ExternalAccountSpec, data extsvc.ExternalAccountData) error {
				newUserAccounts = append(newUserAccounts, spec)
				return nil
			}
			Mocks.ExternalAccounts.List = func(ExternalAccountsListOptions) ([]*extsvc.ExternalAccount, error) {
				return q.userAccounts, nil
			}

			filteredRepos, err := authzFilter(ctx, q.repos, q.perm)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(filteredRepos, q.expFilteredRepos) {
				a := make([]api.RepoURI, len(filteredRepos))
				for i, v := range filteredRepos {
					a[i] = v.URI
				}
				e := make([]api.RepoURI, len(q.expFilteredRepos))
				for i, v := range q.expFilteredRepos {
					e[i] = v.URI
				}
				t.Errorf("Expected filtered repos\n\t%v\n, but got\n\t%v", e, a)
			}
			if !reflect.DeepEqual(newUserAccounts, q.expNewUserAccounts) {
				t.Errorf("Expected new accounts created %v, but got %v", q.expNewUserAccounts, newUserAccounts)
			}
		}
	}
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

type MockAuthzProvider struct {
	serviceID   string
	serviceType string

	// okServiceIDs indicate services whose external accounts will be straightforwardly translated
	// into external accounts belonging to this provider.
	okServiceIDs map[string]struct{}

	perms map[extsvc.ExternalAccount]map[api.RepoURI]map[authz.Perm]bool
	repos map[api.RepoURI]struct{}
}

func (m *MockAuthzProvider) FetchAccount(ctx context.Context, user *types.User, current []*extsvc.ExternalAccount) (mine *extsvc.ExternalAccount, err error) {
	for _, acct := range current {
		if _, ok := m.okServiceIDs[acct.ServiceID]; ok {
			myAcct := *acct
			myAcct.ServiceType = m.serviceType
			myAcct.ServiceID = m.serviceID
			if _, acctExistsInPerms := m.perms[myAcct]; acctExistsInPerms {
				return &myAcct, nil
			}
		}
	}
	return nil, nil
}

func (m *MockAuthzProvider) RepoPerms(ctx context.Context, acct *extsvc.ExternalAccount, repos map[authz.Repo]struct{}) (map[api.RepoURI]map[authz.Perm]bool, error) {
	retPerms := make(map[api.RepoURI]map[authz.Perm]bool)
	repos, _ = m.Repos(ctx, repos)

	if acct == nil {
		acct = &extsvc.ExternalAccount{}
	}
	if _, existsInPerms := m.perms[*acct]; !existsInPerms {
		acct = &extsvc.ExternalAccount{}
	}

	var userPerms map[api.RepoURI]map[authz.Perm]bool = m.perms[*acct]
	for repo := range repos {
		retPerms[repo.URI] = make(map[authz.Perm]bool)
		for k, v := range userPerms[repo.URI] {
			retPerms[repo.URI][k] = v
		}
	}
	return retPerms, nil
}

func (m *MockAuthzProvider) Repos(ctx context.Context, repos map[authz.Repo]struct{}) (mine map[authz.Repo]struct{}, others map[authz.Repo]struct{}) {
	mine, others = make(map[authz.Repo]struct{}), make(map[authz.Repo]struct{})
	for repo := range repos {
		if _, ok := m.repos[repo.URI]; ok {
			mine[repo] = struct{}{}
		} else {
			others[repo] = struct{}{}
		}
	}
	return mine, others
}

func (m *MockAuthzProvider) ServiceID() string   { return m.serviceID }
func (m *MockAuthzProvider) ServiceType() string { return m.serviceType }
