package managedschemas

import (
	"context"
	"github.com/google/go-github/github"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestGitHubRepository_ReleaseFeed(t *testing.T) {
	// Skip until we can mock http client for github
	t.Skip()

	assert := require.New(t)
	repo := GitHubRepository{
		Repo:   "panther-analysis",
		Owner:  "panther-labs",
		Client: github.NewClient(nil),
	}
	feed, err := repo.ReleaseFeed(context.Background(), "v0.0.0")
	assert.NoError(err)
	assert.NotEmpty(feed)
}
