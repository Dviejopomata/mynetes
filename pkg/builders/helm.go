package builders

import (
	"encoding/json"
	"fmt"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/imdario/mergo"
	"github.com/pkg/errors"
	"github.com/Dviejopomata/mynetes/config"
	"github.com/Dviejopomata/mynetes/log"
	"github.com/Dviejopomata/mynetes/pkg/progressbar"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/helm/pkg/chartutil"
	"k8s.io/helm/pkg/helm"
	"k8s.io/helm/pkg/proto/hapi/release"
	helmservices "k8s.io/helm/pkg/proto/hapi/services"
	"k8s.io/kubernetes/pkg/credentialprovider"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
)

type HelmOptions struct {
	Pw          progressbar.IProgressBar
	Client      *helm.Client
	Config      config.ApplicationYaml
	DockerCli   *client.Client
	Environment config.Environment
	K8sClient   *kubernetes.Clientset
	Auth        types.AuthConfig
}
type HelmDeleteOptions struct {
	Client      *helm.Client
	Config      config.ApplicationYaml
	DockerCli   *client.Client
	Environment config.Environment
	K8sClient   *kubernetes.Clientset
}
type HelmResponse struct {
	Release *release.Release
}

type HelmDeleteResponse struct {
	Release *release.Release
}

func DeleteK8s(options HelmDeleteOptions) (*helmservices.UninstallReleaseResponse, error) {
	appConfig := options.Config
	namespace := options.Environment.Name
	releaseName := fmt.Sprintf("%s-%s", appConfig.App, namespace)
	response, err := options.Client.DeleteRelease(releaseName, helm.DeletePurge(true))
	if err != nil {
		return nil, err
	}
	return response, nil
}

func DeployK8s(options HelmOptions) (*HelmResponse, error) {
	dockerCli := options.DockerCli
	appConfig := options.Config
	env := options.Environment
	var chart *Chart
	pullSecret := "registry"

	dockercfgAuth, err := handleDockerCfgJsonContent(
		options.Auth.Username,
		options.Auth.Password,
		options.Auth.Email,
		options.Auth.ServerAddress,
	)
	if err != nil {
		return nil, err
	}

	namespace := options.Environment.Name
	nsK8s := options.K8sClient.CoreV1().Namespaces()
	var ns *corev1.Namespace
	ns, err = nsK8s.Get(namespace, metav1.GetOptions{})
	if err != nil {
		// create
		ns, err = nsK8s.Create(&corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: namespace,
			},
		})
		if err != nil {
			log.Printf("Failed to created namespace %s", namespace)
			return nil, err
		}
		log.Printf("Namespace created %s", ns.Name)
	}
	secret, err := options.K8sClient.CoreV1().Secrets(namespace).Get(pullSecret, metav1.GetOptions{})

	if err != nil {
		// create
		secret = &corev1.Secret{
			Type: corev1.SecretTypeDockerConfigJson,
			Data: map[string][]byte{
				corev1.DockerConfigJsonKey: dockercfgAuth,
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      pullSecret,
				Namespace: namespace,
			},
		}
		csStep := options.Pw.NewStep("Creating kubernetes secret")
		secret, err = options.K8sClient.CoreV1().Secrets(namespace).Create(secret)
		if err != nil {
			log.Printf("Failed to created secret %s", pullSecret)
			csStep.Error(err)
			return nil, err
		}
		csStep.Done()
	}

	emptyChart, err := filepath.Abs("./charts/empty")
	if err != nil {
		return nil, err
	}
	chart = &Chart{
		Chart:        emptyChart,
		Name:         "chartPath",
		Charts:       []*Chart{},
		Values:       map[string]interface{}{},
		Dependencies: []*Dependency{},
		Options: ChartOptions{
			Name:        fmt.Sprintf("%s-%s", appConfig.App, env.Name),
			Version:     "0.1.0",
			ApiVersion:  "v1",
			AppVersion:  "1.0",
			Description: "Root chart",
		},
	}
	for name, handler := range appConfig.Handlers {
		servicePort := 80
		replicas := 1
		buildOptions := BuildOptions{
			Environment: env,
			Client:      dockerCli,
			Config:      appConfig,
			Handlername: name,
			Handler:     handler,
			Auth:        options.Auth,
		}
		buildAndPushStep := options.Pw.NewStep(fmt.Sprintf("Building and pushing image, Handler=%s Environment=%s", name, env.Name))
		//var body bytes.Buffer
		imageInspect, err := BuildAndPush(buildOptions, os.Stdout)
		if err != nil {
			buildAndPushStep.Error(err)
			return nil, err
		}
		buildAndPushStep.Done()
		basicChart, err := filepath.Abs("./charts/base")
		if err != nil {
			return nil, err
		}
		envVariables := []config.EnvironmentVariable{
			{Name: "PORT", Value: "80"},
			{Name: "APP_NAME", Value: appConfig.App},
			{Name: "ENV_NAME", Value: env.Name},
			{Name: "EXTERNAL_DOMAIN", Value: env.Domain},
		}
		envVariables = append(envVariables, env.EnvVars...)
		livenessPath := ""
		livenessEnabled := handler.Liveness != nil && *handler.Liveness != ""
		if livenessEnabled {
			livenessPath = *handler.Liveness
		}
		annotations := map[string]string{}
		if handler.Rewrite != "" {
			annotations["nginx.ingress.kubernetes.io/rewrite-target"] = handler.Rewrite
		}

		dockerOptions, ok := env.HandlerOptions[name]
		if ok {
			if err := mergo.Merge(&handler, dockerOptions); err != nil {
				return nil, errors.Wrapf(err, "Failed to merge handler options %s", name)
			}
		}
		domain := env.Domain
		if handler.Domain != "" {
			domain = handler.Domain
		}
		handlerChart := &Chart{
			Chart: basicChart,
			Name:  fmt.Sprintf("%s-%s-%s", appConfig.App, env.Name, name),
			Options: ChartOptions{
				Name:        name,
				Version:     "0.1.0",
				ApiVersion:  "v1",
				AppVersion:  "1.0",
				Description: fmt.Sprintf("Description of %s", name),
			},
			Dependencies: []*Dependency{},
			Charts:       []*Chart{},
			Values: map[string]interface{}{
				"pullSecrets":  []string{"registry"},
				"replicaCount": replicas,
				"ports": &map[string]interface{}{
					"http": servicePort,
				},
				"isLivenessDisabled": !livenessEnabled,
				"liveness":           livenessPath,
				"env":                envVariables,
				"image": map[string]interface{}{
					"repository": imageInspect.Repository,
					"tag":        imageInspect.Version,
					"pullPolicy": "IfNotPresent",
				},
				"service": map[string]interface{}{
					"type": "ClusterIP",
					"port": servicePort,
				},
				"ingress": map[string]interface{}{
					"annotations": annotations,
					"enabled":     true,
					"hosts":       []string{domain},
					"path":        handler.URL,
				},
			},
		}
		chart.AddChart(handlerChart)
	}

	releaseName := fmt.Sprintf("%s-%s", appConfig.App, namespace)
	chartPath, err := ioutil.TempDir("", "na-k8s-build-git")
	if err != nil {
		return nil, err
	}
	bcStep := options.Pw.NewStep("Building chart")
	log.Printf("Chart path %s", chartPath)
	err = chart.DumpAll(chartPath, DumpOptions{})
	if err != nil {
		bcStep.Error(err)
		return nil, err
	}
	bcStep.Done()
	bcStep = options.Pw.NewStep(fmt.Sprintf("Deploying chart %s", releaseName))
	chartRelease, err := installChart(options, releaseName, chartPath)
	if err != nil {
		bcStep.Error(err)
		return nil, err
	}
	bcStep.Done()
	return &HelmResponse{
		Release: chartRelease,
	}, nil
}

func installChart(options HelmOptions, releaseName, chartPath string) (*release.Release, error) {
	var err error
	achart, err := chartutil.Load(chartPath)
	hc := options.Client
	releaseHistory, err := hc.ReleaseHistory(releaseName, helm.WithMaxHistory(1))
	var res *release.Release
	if err != nil {
		// does not exists
		var response *helmservices.InstallReleaseResponse
		response, err = hc.InstallReleaseFromChart(
			achart,
			options.Environment.Name,
			helm.ReleaseName(releaseName),
			//helm.ValueOverrides(fileBytes),
		)

		if err == nil {
			res = response.Release
		}
	}
	if err == nil {
		log.Println(releaseHistory)
		// does exists
		statusResponse, err := hc.ReleaseStatus(releaseName)
		if err != nil {
			return nil, err
		}
		var updatedOptions []helm.UpdateOption
		log.Printf("Release status %s", statusResponse.Info.Status.Code)
		if statusResponse.Info.Status.Code != release.Status_DEPLOYED {
			updatedOptions = append(updatedOptions, helm.UpgradeRecreate(true))
		}
		var response *helmservices.UpdateReleaseResponse
		response, err = hc.UpdateReleaseFromChart(
			releaseName,
			achart,
			updatedOptions...,
		)
		if err == nil {
			res = response.Release
		}
	}
	return res, err
}

func handleDockerCfgJsonContent(username, password, email, server string) ([]byte, error) {
	dockercfgAuth := credentialprovider.DockerConfigEntry{
		Username: username,
		Password: password,
		Email:    email,
	}

	dockerCfgJson := credentialprovider.DockerConfigJson{
		Auths: map[string]credentialprovider.DockerConfigEntry{server: dockercfgAuth},
	}

	return json.Marshal(dockerCfgJson)
}

type Dependency struct {
	Name       string
	Version    string
	Repository string
	Condition  string
	Values     map[string]interface{}
}

type Chart struct {
	Name         string
	Chart        string
	Values       map[string]interface{}
	Charts       []*Chart
	Dependencies []*Dependency
	Options      ChartOptions
}

func (c *Chart) AddChart(chart *Chart) {
	c.Charts = append(c.Charts, chart)
}

func (c *Chart) AddDependency(dependency *Dependency) {
	c.Dependencies = append(c.Dependencies, dependency)
}

type DumpOptions struct {
}

const VALUES_YAML = "values.yaml"
const CHARTS_YAML = "Chart.yaml"
const REQUIREMENTS_YAML = "requirements.yaml"

type ChartOptions struct {
	ApiVersion  string
	AppVersion  string
	Description string
	Name        string
	Version     string
}

func (c *Chart) DumpAll(outputDir string, options DumpOptions) error {
	err := c.Dump(outputDir, options)
	if err != nil {
		return err
	}
	for _, d := range c.Dependencies {
		c.Values[d.Name] = d.Values
	}
	for _, chart := range c.Charts {
		err := chart.DumpAll(filepath.Join(outputDir, "charts", chart.Name), options)
		if err != nil {
			return err
		}
	}
	return nil
}
func (c *Chart) Dump(outputDir string, options DumpOptions) error {
	chartPath, err := filepath.Abs(c.Chart)
	if err != nil {
		return err
	}
	templatesPath := filepath.Join(chartPath, "templates")
	matches, err := filepath.Glob(filepath.Join(templatesPath, "*"))
	if err != nil {
		return err
	}
	templates := map[string][]byte{}
	destTemplatesPath := filepath.Join(outputDir, "templates")
	err = os.MkdirAll(destTemplatesPath, os.ModePerm)
	if err != nil {
		return err
	}
	for _, match := range matches {
		matched, err := regexp.MatchString(".*\\..*(yaml|tpl)$", match)
		if err != nil {
			return err
		}
		if matched {
			path, err := filepath.Rel(templatesPath, match)
			if err != nil {
				return err
			}
			fileBytes, err := ioutil.ReadFile(match)
			if err != nil {
				return err
			}
			templates[path] = fileBytes
			f := filepath.Join(destTemplatesPath, filepath.Base(match))
			log.Printf("Match %s Out %s ", match, f)

			err = ioutil.WriteFile(f, fileBytes, os.ModePerm)
			if err != nil {
				return err
			}
		}
	}

	var dependencies []map[string]interface{}
	for _, d := range c.Dependencies {
		dependencies = append(dependencies, map[string]interface{}{
			"Version":    d.Version,
			"Name":       d.Name,
			"Repository": d.Repository,
			"Condition":  d.Condition,
		})
		c.Values[d.Name] = d.Values
	}
	requirementsBytes, err := yaml.Marshal(&map[string]interface{}{
		"dependencies": dependencies,
	})
	if err != nil {
		return err
	}
	bytesValues, err := yaml.Marshal(c.Values)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(filepath.Join(outputDir, VALUES_YAML), bytesValues, os.ModePerm)
	if err != nil {
		return err
	}
	chartBytes, err := yaml.Marshal(c.Options)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(filepath.Join(outputDir, CHARTS_YAML), chartBytes, os.ModePerm)
	if err != nil {
		return err
	}
	if len(c.Dependencies) > 0 {
		err = ioutil.WriteFile(filepath.Join(outputDir, REQUIREMENTS_YAML), requirementsBytes, os.ModePerm)
		if err != nil {
			return err
		}
		cmd := exec.Command("helm", "dependency", "update")
		cmd.Dir = outputDir
		err := cmd.Run()
		if err != nil {
			log.Println("Error updating dependencies")
			return err
		}
		cmd = exec.Command("helm", "dependency", "build")
		cmd.Dir = outputDir
		err = cmd.Run()
		if err != nil {
			log.Println("Error building dependencies")
			return err
		}
	}

	return nil
}
