package gitlab

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/sourcegraph/sourcegraph/cmd/frontend/internal/auth"
	"github.com/sourcegraph/sourcegraph/cmd/frontend/internal/authz"
	"github.com/sourcegraph/sourcegraph/cmd/frontend/types"
	"github.com/sourcegraph/sourcegraph/pkg/api"
	"github.com/sourcegraph/sourcegraph/pkg/conf/reposource"
	"github.com/sourcegraph/sourcegraph/pkg/extsvc"
	"github.com/sourcegraph/sourcegraph/pkg/extsvc/gitlab"
	"github.com/sourcegraph/sourcegraph/pkg/rcache"
	log15 "gopkg.in/inconshreveable/log15.v2"
)

type pcache interface {
	Get(key string) ([]byte, bool)
	Set(key string, b []byte)
	Delete(key string)
}

type GitLabAuthzProvider struct {
	client          *gitlab.Client
	clientURL       *url.URL
	codeHost        *gitlab.CodeHost
	repoPathPattern string
	cache           pcache

	// matchPattern, if non-empty, should be a string that may contain a prefix "*/" or suffix "/*".
	// If it satisfies neither, *no* repositories will be matched.  If empty, we match on the value
	// of ExternalRepoSpec (fetched from the DB).
	matchPattern string

	// gitlabProvider is the string that should be passed to the `provider` URL query parameter when
	// looking up the user via the GitLab API. It is the identifier to GitLab of the same
	// authenetication provider as is identified by authnConfigID
	gitlabProvider string

	// authnConfigID is the config identifier that identifies the authentication provider to use
	// when no GitLab external account exists. It corresponds to the auth.ProviderInfo.ConfigID
	// field.
	authnConfigID auth.ProviderConfigID

	// userNativeUsername, if true, makes this provider compute the correspondence to GitLab user
	// using the Sourcegraph username. This is highly unsafe (as the username is mutable and not
	// intrinsically tied ot the GitLab username) and should only be used in development/testing
	// environments.
	useNativeUsername bool
}

var _ authz.AuthzProvider = ((*GitLabAuthzProvider)(nil))

type cacheVal struct {
	// Repos is the list of repositories to which the user has access.
	Repos map[api.RepoURI]struct{} `json:"repos"`
}

type GitLabAuthzProviderOp struct {
	BaseURL        *url.URL
	AuthnConfigID  auth.ProviderConfigID
	GitLabProvider string

	// SudoToken is an access tokens with sudo *and* api scope.
	//
	// 🚨 SECURITY: This value contains secret information that must not be shown to non-site-admins.
	SudoToken         string
	RepoPathPattern   string
	MatchPattern      string
	CacheTTL          time.Duration
	UseNativeUsername bool

	MockCache pcache
}

func NewGitLabAuthzProvider(op GitLabAuthzProviderOp) *GitLabAuthzProvider {
	p := &GitLabAuthzProvider{
		client:            gitlab.NewClient(op.BaseURL, op.SudoToken, nil),
		clientURL:         op.BaseURL,
		codeHost:          gitlab.NewCodeHost(op.BaseURL),
		repoPathPattern:   op.RepoPathPattern,
		matchPattern:      op.MatchPattern,
		cache:             op.MockCache,
		authnConfigID:     op.AuthnConfigID,
		gitlabProvider:    op.GitLabProvider,
		useNativeUsername: op.UseNativeUsername,
	}
	if p.cache == nil {
		p.cache = rcache.NewWithTTL(fmt.Sprintf("gitlabAuthz:%s", op.BaseURL.String()), int(math.Ceil(op.CacheTTL.Seconds())))
	}
	return p
}

func (p *GitLabAuthzProvider) ServiceID() string {
	return p.codeHost.ServiceID()
}

func (p *GitLabAuthzProvider) ServiceType() string {
	return p.codeHost.ServiceType()
}

func (p *GitLabAuthzProvider) RepoPerms(ctx context.Context, account *extsvc.ExternalAccount, repos map[authz.Repo]struct{}) (map[api.RepoURI]map[authz.Perm]bool, error) {
	accountID := "" // empty means public / unauthenticated to the code host
	if account != nil {
		accountID = account.AccountID
	}

	myRepos, _ := p.Repos(ctx, repos)
	var accessibleRepos map[api.RepoURI]struct{}
	if r, exists := p.getCachedAccessList(accountID); exists {
		accessibleRepos = r
	} else if account.ServiceID == p.codeHost.ServiceID() && account.ServiceType == p.codeHost.ServiceType() {
		var err error
		accessibleRepos, err = p.fetchUserAccessList(ctx, accountID)
		if err != nil {
			return nil, err
		}

		accessibleReposB, err := json.Marshal(cacheVal{Repos: accessibleRepos})
		if err != nil {
			return nil, err
		}
		p.cache.Set(accountID, accessibleReposB)
	}

	perms := make(map[api.RepoURI]map[authz.Perm]bool)
	for repo := range myRepos {
		if _, ok := accessibleRepos[repo.URI]; ok {
			perms[repo.URI] = map[authz.Perm]bool{authz.Read: true}
		} else {
			perms[repo.URI] = map[authz.Perm]bool{}
		}
	}

	return perms, nil
}

func (p *GitLabAuthzProvider) Repos(ctx context.Context, repos map[authz.Repo]struct{}) (mine map[authz.Repo]struct{}, others map[authz.Repo]struct{}) {
	if p.matchPattern != "" {
		if mt, matchString, err := ParseMatchPattern(p.matchPattern); err == nil {
			if mine, others, err = reposByMatchPattern(mt, matchString, repos); err == nil {
				return mine, others
			} else {
				log15.Error("Unexpected error executing matchPattern", "matchPattern", p.matchPattern, "err", err)
			}
		} else {
			log15.Error("Error parsing matchPattern", "err", err)
		}
	}

	mine, others = make(map[authz.Repo]struct{}), make(map[authz.Repo]struct{})
	for repo := range repos {
		if p.codeHost.IsHostOf(&repo.ExternalRepoSpec) {
			mine[repo] = struct{}{}
		} else {
			others[repo] = struct{}{}
		}
	}
	return mine, others
}

func (p *GitLabAuthzProvider) FetchAccount(ctx context.Context, user *types.User, current []*extsvc.ExternalAccount) (mine *extsvc.ExternalAccount, err error) {
	if user == nil {
		return nil, nil
	}

	var glUser *gitlab.User
	if p.useNativeUsername {
		glUser, err = p.fetchAccountByUsername(ctx, user.Username)
	} else {
		// resolve the GitLab account using the authn provider (specified by p.AuthnConfigID)
		authnProvider := getProviderByConfigID(p.authnConfigID)
		if authnProvider == nil {
			return nil, nil
		}
		var authnAcct *extsvc.ExternalAccount
		for _, acct := range current {
			if acct.ServiceID == authnProvider.CachedInfo().ServiceID && acct.ServiceType == authnProvider.ConfigID().Type {
				authnAcct = acct
				break
			}
		}
		if authnAcct == nil {
			return nil, nil
		}
		glUser, err = p.fetchAccountByExternalUID(ctx, authnAcct.AccountID)
	}
	if err != nil {
		return nil, err
	}
	if glUser == nil {
		return nil, nil
	}

	jsonGLUser, err := json.Marshal(glUser)
	if err != nil {
		return nil, err
	}
	accountData := json.RawMessage(jsonGLUser)
	glExternalAccount := extsvc.ExternalAccount{
		UserID: user.ID,
		ExternalAccountSpec: extsvc.ExternalAccountSpec{
			ServiceType: p.codeHost.ServiceType(),
			ServiceID:   p.codeHost.ServiceID(),
			AccountID:   strconv.Itoa(int(glUser.ID)),
		},
		ExternalAccountData: extsvc.ExternalAccountData{
			AccountData: &accountData,
		},
	}
	return &glExternalAccount, nil
}

func (p *GitLabAuthzProvider) fetchAccountByExternalUID(ctx context.Context, uid string) (*gitlab.User, error) {
	q := make(url.Values)
	q.Add("extern_uid", uid)
	q.Add("provider", p.gitlabProvider)
	q.Add("per_page", "2")
	glUsers, _, err := p.client.ListUsers(ctx, "users?"+q.Encode())
	if err != nil {
		return nil, err
	}
	if len(glUsers) >= 2 {
		return nil, fmt.Errorf("failed to determine unique GitLab user for query %q", q.Encode())
	}
	if len(glUsers) == 0 {
		return nil, nil
	}
	return glUsers[0], nil
}

func (p *GitLabAuthzProvider) fetchAccountByUsername(ctx context.Context, username string) (*gitlab.User, error) {
	q := make(url.Values)
	q.Add("username", username)
	q.Add("per_page", "2")
	glUsers, _, err := p.client.ListUsers(ctx, "users?"+q.Encode())
	if err != nil {
		return nil, err
	}
	if len(glUsers) >= 2 {
		return nil, fmt.Errorf("failed to determine unique GitLab user for query %q", q.Encode())
	}
	if len(glUsers) == 0 {
		return nil, nil
	}
	return glUsers[0], nil
}

func reposByMatchPattern(mt matchType, matchString string, repos map[authz.Repo]struct{}) (mine map[authz.Repo]struct{}, others map[authz.Repo]struct{}, err error) {
	mine, others = make(map[authz.Repo]struct{}), make(map[authz.Repo]struct{})
	for repo := range repos {
		switch mt {
		case matchSubstring:
			if strings.Contains(string(repo.URI), matchString) {
				mine[repo] = struct{}{}
			} else {
				others[repo] = struct{}{}
			}
		case matchPrefix:
			if strings.HasPrefix(string(repo.URI), matchString) {
				mine[repo] = struct{}{}
			} else {
				others[repo] = struct{}{}
			}
		case matchSuffix:
			if strings.HasSuffix(string(repo.URI), matchString) {
				mine[repo] = struct{}{}
			} else {
				others[repo] = struct{}{}
			}
		default:
			return nil, nil, fmt.Errorf("Unrecognized matchType: %v", mt)
		}
	}
	return mine, others, nil
}

// getCachedAccessList returns the list of repositories accessible to a user from the cache and
// whether the cache entry exists.
func (p *GitLabAuthzProvider) getCachedAccessList(accountID string) (map[api.RepoURI]struct{}, bool) {
	// TODO(beyang): trigger best-effort fetch in background if ttl is getting close (but avoid dup refetches)

	cachedReposB, exists := p.cache.Get(accountID)
	if !exists {
		return nil, false
	}
	var r cacheVal
	if err := json.Unmarshal(cachedReposB, &r); err != nil {
		log15.Warn("Failed to unmarshal repo perm cache entry", "err", err.Error())
		p.cache.Delete(accountID)
		return nil, false
	}
	return r.Repos, true
}

// fetchUserAccessList fetches the list of repositories that are readable to a user from the GitLab API.
func (p *GitLabAuthzProvider) fetchUserAccessList(ctx context.Context, glUserID string) (map[api.RepoURI]struct{}, error) {
	q := make(url.Values)
	if glUserID != "" {
		q.Add("sudo", glUserID)
	} else {
		q.Add("visibility", "public")
	}
	q.Add("per_page", "100")

	var allProjs []*gitlab.Project
	var iters = 0
	var pageURL = "projects?" + q.Encode()
	for {
		if iters >= 100 && iters%100 == 0 {
			log15.Warn("Excessively many GitLab API requests to fetch complete user authz list", "iters", iters, "gitlabUserID", glUserID, "host", p.clientURL.String())
		}

		projs, nextPageURL, err := p.client.ListProjects(ctx, pageURL)
		if err != nil {
			return nil, err
		}

		allProjs = append(allProjs, projs...)
		if nextPageURL == nil {
			break
		}
		pageURL = *nextPageURL
		iters++
	}

	accessibleRepos := make(map[api.RepoURI]struct{})
	for _, proj := range allProjs {
		repoURI := reposource.GitLabRepoURI(p.repoPathPattern, p.clientURL.Hostname(), proj.PathWithNamespace)
		accessibleRepos[repoURI] = struct{}{}
	}
	return accessibleRepos, nil
}

type matchType string

const (
	matchPrefix    matchType = "prefix"
	matchSuffix    matchType = "suffix"
	matchSubstring matchType = "substring"
)

func ParseMatchPattern(matchPattern string) (mt matchType, matchString string, err error) {
	startGlob := strings.HasPrefix(matchPattern, "*/")
	endGlob := strings.HasSuffix(matchPattern, "/*")
	matchString = strings.TrimPrefix(strings.TrimSuffix(matchPattern, "/*"), "*/")

	switch {
	case startGlob && endGlob:
		return matchSubstring, "/" + matchString + "/", nil
	case startGlob:
		return matchSuffix, "/" + matchString, nil
	case endGlob:
		return matchPrefix, matchString + "/", nil
	default:
		// If no wildcard, then match no repositories
		return "", "", errors.New("matchPattern should start with \"*/\" or end with \"/*\"")
	}
}

var getProviderByConfigID = auth.GetProviderByConfigID
