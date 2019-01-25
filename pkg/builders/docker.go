package builders

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/builder/dockerignore"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/archive"
	"github.com/docker/docker/pkg/idtools"
	"github.com/docker/docker/pkg/jsonmessage"
	"github.com/docker/docker/pkg/term"
	"github.com/docker/docker/pkg/urlutil"
	"github.com/pkg/errors"
	"github.com/satori/go.uuid"
	"github.com/Dviejopomata/mynetes/config"
	"github.com/Dviejopomata/mynetes/log"
	"github.com/Dviejopomata/mynetes/pkg/utils"
	"golang.org/x/crypto/ssh"
	"gopkg.in/src-d/go-git.v4"
	"gopkg.in/src-d/go-git.v4/plumbing"
	"gopkg.in/src-d/go-git.v4/plumbing/transport"
	go_git_ssh "gopkg.in/src-d/go-git.v4/plumbing/transport/ssh"
	"io"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

type OutStream struct {
	io.Writer
}

func (o *OutStream) FD() uintptr {
	return 0
}
func (o *OutStream) IsTerminal() bool {
	return true
}

type BuildOptions struct {
	Environment config.Environment
	Handler     config.Handler
	Client      *client.Client
	Config      config.ApplicationYaml
	Handlername string
	Auth        types.AuthConfig
}

type BuildAndPushResult struct {
	Inspect    *types.ImageInspect
	Tag        string
	Version    string
	Repository string
}

func BuildAndPush(options BuildOptions, w io.Writer) (*BuildAndPushResult, error) {
	response, err := Build(options)
	if err != nil {
		return nil, err
	}
	aux := func(msg jsonmessage.JSONMessage) {
		var result types.BuildResult
		if err := json.Unmarshal(*msg.Aux, &result); err != nil {
			log.Fatalf("Failed to parse aux message: %s", err)
		}
	}
	out := w
	fd, isTerminal := term.GetFdInfo(out)
	err = jsonmessage.DisplayJSONMessagesStream(response.ImageBuildResponse.Body, out, fd, isTerminal, aux)
	if err != nil {
		return nil, err
	}
	tag := response.BuildOptions.Tags[0]
	log.Infof("Image %s", tag)
	ctx := context.Background()
	inspect, _, err := options.Client.ImageInspectWithRaw(ctx, tag)
	if err != nil {
		return nil, err
	}
	version := response.Version
	repository := strings.Replace(tag, fmt.Sprintf(":%s", version), "", 1)
	finalVersion := strings.Replace(inspect.ID, "sha256:", "", 1)
	newTag := fmt.Sprintf(
		"%s:%s",
		repository,
		finalVersion,
	)
	err = options.Client.ImageTag(ctx, tag, newTag)
	if err != nil {
		return nil, err
	}
	err = PushImage(newTag, options.Auth, options.Client, w)
	if err != nil {
		return nil, err
	}
	return &BuildAndPushResult{
		Inspect:    &inspect,
		Tag:        newTag,
		Version:    finalVersion,
		Repository: repository,
	}, err
}

type BuildResponse struct {
	ImageBuildResponse *types.ImageBuildResponse
	BuildOptions       types.ImageBuildOptions
	Version            string
}

func Build(options BuildOptions) (*BuildResponse, error) {
	var contextDir string
	var err error
	switch {
	case isLocalDir(options.Environment.Repository):
		contextDir = options.Environment.Repository
	case urlutil.IsGitURL(options.Environment.Repository):
		contextDir, err = cloneRepo(options.Environment.Repository)
		defer os.RemoveAll(contextDir)
	}
	// if file is in subfolder, the context should be in the subfolder
	subfolder := filepath.Dir(options.Handler.File)
	if subfolder != "" {
		contextDir = filepath.Join(contextDir, subfolder)
	}

	if err != nil {
		return nil, errors.Wrapf(err, "Failed to clone the repository")
	}
	log.Printf("Repository cloned to %s", contextDir)
	excludes, err := GetDockerIgnore(contextDir)
	if err != nil {
		return nil, err
	}

	dockerfilePath := "Dockerfile"
	dockerfilePath = filepath.Base(options.Handler.File)

	buildCtx, err := archive.TarWithOptions(contextDir, &archive.TarOptions{
		ExcludePatterns: excludes,
		ChownOpts:       &idtools.Identity{UID: 0, GID: 0},
	})
	if err != nil {
		return nil, err
	}
	dockerCli := options.Client

	ctx := context.Background()
	dockerCli.NegotiateAPIVersion(ctx)
	version := uuid.NewV4().String()
	dockerImage, err := getDockerImageUrl(options.Environment.Repository, options.Auth)
	if err != nil {
		return nil, err
	}
	tag := fmt.Sprintf("%s/%s:%s", dockerImage, options.Handlername, version)

	buildOptions := types.ImageBuildOptions{
		Tags: []string{tag}, NetworkMode: "host",
		Dockerfile: dockerfilePath,
	}
	response, err := dockerCli.ImageBuild(ctx, buildCtx, buildOptions)
	if err != nil {
		return nil, errors.Wrapf(err, "Unable to build image")
	}
	return &BuildResponse{
		ImageBuildResponse: &response,
		BuildOptions:       buildOptions,
		Version:            version,
	}, nil
}
func GetDockerIgnore(contextDir string) ([]string, error) {
	var excludes []string

	f, err := os.Open(filepath.Join(contextDir, ".dockerignore"))
	switch {
	case os.IsNotExist(err):
		return excludes, nil
	case err != nil:
		return nil, err
	}
	defer f.Close()

	return dockerignore.ReadAll(f)
}

func PushImage(tag string, authConfig types.AuthConfig, dockerCli *client.Client, w io.Writer) error {
	ctx := context.Background()
	encodedAuth, err := encodeAuthToBase64(authConfig)
	if err != nil {
		return err
	}

	res, err := dockerCli.ImagePush(ctx, tag, types.ImagePushOptions{
		RegistryAuth: encodedAuth,
	})
	if err != nil {
		return err
	}

	err = jsonmessage.DisplayJSONMessagesToStream(res, &OutStream{Writer: w}, nil)
	if err != nil {
		return err
	}
	return nil
}

func isLocalDir(c string) bool {
	_, err := os.Stat(c)
	return err == nil
}

func encodeAuthToBase64(authConfig types.AuthConfig) (string, error) {
	buf, err := json.Marshal(authConfig)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(buf), nil
}

func splitDockerImage(tag string) ([]string, error) {
	split := strings.Split(tag, ":")
	if len(split) < 1 || len(split) > 2 {
		return split, errors.New(fmt.Sprintf("Tag %s does not have a version", tag))
	}
	if len(split) == 1 {
		split = append(split, "latest")
	}
	return split, nil
}
func getDockerImageUrl(url string, auth types.AuthConfig) (string, error) {
	repo, err := parseRemoteURL(url)
	if err != nil {
		return "", err
	}
	return auth.ServerAddress + repo.path, nil

}
func getSshKeyAuth(privateSshKeyFile string) (transport.AuthMethod, error) {
	var auth transport.AuthMethod
	sshKey, err := ioutil.ReadFile(privateSshKeyFile)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.ParsePrivateKey([]byte(sshKey))
	if err != nil {
		return nil, err
	}

	auth = &go_git_ssh.PublicKeys{
		User:   "git",
		Signer: signer,
	}
	auth.(*go_git_ssh.PublicKeys).HostKeyCallback = ssh.InsecureIgnoreHostKey()
	return auth, nil
}

func cloneRepo(url string) (string, error) {
	repo, err := parseRemoteURL(url)
	if err != nil {
		return "", err
	}
	directory, err := ioutil.TempDir("", "docker-build-git")
	if err != nil {
		return "", err
	}
	pkFile := filepath.Join(utils.GetSshDirectory(), getHostByGitUrl(url))
	auth, err := getSshKeyAuth(pkFile)
	if err != nil {
		return "", err
	}
	r, err := git.PlainClone(directory, false, &git.CloneOptions{
		URL:               url,
		RecurseSubmodules: git.DefaultSubmoduleRecursionDepth,
		Auth:              auth,
	})
	if err != nil {
		return "", err
	}
	// ... retrieving the branch being pointed by HEAD
	ref, err := r.Head()
	if err != nil {
		return "", err
	}
	// ... retrieving the commit object
	_, err = r.CommitObject(ref.Hash())
	if err != nil {
		return "", err
	}
	w, err := r.Worktree()
	if err != nil {
		return "", err
	}

	b := plumbing.ReferenceName(fmt.Sprintf("refs/remotes/origin/%s", repo.ref))
	remoteRef, err := r.Reference(b, true)
	if err != nil {
		return "", err
	}
	newRef := plumbing.NewHashReference("refs/heads/newbranch", remoteRef.Hash())

	err = r.Storer.SetReference(newRef)
	if err != nil {
		return "", err
	}

	err = w.Checkout(&git.CheckoutOptions{
		Branch: newRef.Name(),
		Create: false,
	})
	if err != nil {
		return "", err
	}
	return directory, nil
}
func getHostByGitUrl(url string) string {
	uri := strings.Replace(url, "git@", "", 1)
	return strings.Split(uri, ":")[0]
}

type gitRepo struct {
	remote string
	ref    string
	subdir string
	path   string
}

func parseRemoteURL(remoteURL string) (gitRepo, error) {
	repo := gitRepo{}

	if !isGitTransport(remoteURL) {
		remoteURL = "https://" + remoteURL
	}

	var fragment string
	if strings.HasPrefix(remoteURL, "git@") {
		// git@.. is not an URL, so cannot be parsed as URL
		parts := strings.SplitN(remoteURL, "#", 2)

		repo.remote = parts[0]
		if len(parts) == 2 {
			fragment = parts[1]
		}
		repo.ref, repo.subdir = getRefAndSubdir(fragment)
		parts = strings.Split(repo.remote, ":")
		if len(parts) != 2 {
			return repo, errors.New("Couldn't get the path")
		}
		repo.path = fmt.Sprintf("/%s", strings.Replace(parts[1], ".git", "", 1))
	} else {
		u, err := url.Parse(remoteURL)
		if err != nil {
			return repo, err
		}

		repo.ref, repo.subdir = getRefAndSubdir(u.Fragment)
		u.Fragment = ""
		repo.remote = u.String()
		repo.path = u.Path
	}
	return repo, nil
}

func getRefAndSubdir(fragment string) (ref string, subdir string) {
	refAndDir := strings.SplitN(fragment, ":", 2)
	ref = "master"
	if len(refAndDir[0]) != 0 {
		ref = refAndDir[0]
	}
	if len(refAndDir) > 1 && len(refAndDir[1]) != 0 {
		subdir = refAndDir[1]
	}
	return
}

func isGitTransport(str string) bool {
	return urlutil.IsURL(str) || strings.HasPrefix(str, "git://") || strings.HasPrefix(str, "git@")
}
