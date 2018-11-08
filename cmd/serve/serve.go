// Copyright © 2018 NAME HERE <EMAIL ADDRESS>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package serve

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/api/types/volume"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/archive"
	"github.com/docker/go-connections/nat"
	"github.com/gin-gonic/gin"
	"github.com/imdario/mergo"
	"github.com/minio/minio-go"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/superwhiskers/yaml"
	"gitlab.nextagilesoft.com/saas2/core/config"
	"gitlab.nextagilesoft.com/saas2/core/log"
	"gitlab.nextagilesoft.com/saas2/core/pkg/builders"
	"gitlab.nextagilesoft.com/saas2/core/pkg/plugins"
	"gitlab.nextagilesoft.com/saas2/core/pkg/progressbar"
	"gitlab.nextagilesoft.com/saas2/core/pkg/utils"
	"io"
	"io/ioutil"
	corev1 "k8s.io/api/core/v1"
	rbac_v1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/helm/cmd/helm/installer"
	"k8s.io/helm/pkg/helm"
	"k8s.io/helm/pkg/helm/portforwarder"
	"k8s.io/helm/pkg/kube"
	"net/http"
	"net/http/pprof"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

const (
	configEnvVariableName  = "CONFIG_URL"
	storageEnvVariableName = "STORAGE_DIR"
	defaultStorageDir      = "./storage"
)

type serveOptions struct {
	Config string
	Host   string
	Port   int64
}

func readFile(c *gin.Context, name string) ([]byte, error) {
	formFile, err := c.FormFile(name)
	if err != nil {
		return nil, err
	}
	file, err := formFile.Open()
	if err != nil {
		return nil, err
	}
	contents, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, err
	}
	return contents, nil
}

type ComputedConfiguration struct {
	K8sClients    map[string]*K8sClient
	DockerClients map[string]*client.Client
	DockerAuths   map[string]types.AuthConfig
	Plugins       map[string]plugins.Plugin
}

//
func NewServeCmd() *cobra.Command {
	o := &serveOptions{}
	*yaml.DefaultMapType = reflect.TypeOf(map[string]interface{}{})

	// serve/serveCmd represents the serve/serve command
	var serveCmd = &cobra.Command{
		Use:   "serve",
		Short: "A brief description of your command",
		Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			serverYaml := config.ServerYaml{}
			r := gin.Default()
			viper.SetConfigFile(o.Config)
			var err error
			err = viper.ReadInConfig()
			if err != nil {
				return err
			}
			err = viper.Unmarshal(&serverYaml)
			if err != nil {
				return err
			}

			storageDir := os.Getenv(storageEnvVariableName)
			if storageDir == "" {
				storageDir = defaultStorageDir
			}
			s3Client, err := minio.New(serverYaml.Minio.Endpoint, serverYaml.Minio.Accesskey, serverYaml.Minio.Secretkey, true)
			if err != nil {
				return errors.Wrapf(err, "Failed to init minio client")
			}
			sshKnownHosts := os.Getenv("SSH_KNOWN_HOSTS")
			if sshKnownHosts != "" {
				if _, err := os.Stat(sshKnownHosts); err != nil {
					// file doesn't exists
					err := os.MkdirAll(filepath.Base(sshKnownHosts), os.ModePerm)
					if err != nil {
						return errors.Wrapf(err, "Failed to create directory for %s", sshKnownHosts)
					}
					file, err := os.Create(sshKnownHosts)
					if err != nil {
						return errors.Wrapf(err, "Failed to create file %s", sshKnownHosts)
					}
					file.Close()
				}
			}

			computedConfiguration := ComputedConfiguration{
				DockerClients: map[string]*client.Client{},
				K8sClients:    map[string]*K8sClient{},
				DockerAuths:   map[string]types.AuthConfig{},
				Plugins:       map[string]plugins.Plugin{},
			}
			postgresqlPlugin, err := plugins.NewPostgresqlPlugin(serverYaml)
			if err != nil {
				return err
			}
			computedConfiguration.Plugins[postgresqlPlugin.Name()] = postgresqlPlugin
			redisPlugin := plugins.NewRedisPlugin()
			computedConfiguration.Plugins[redisPlugin.Name()] = redisPlugin
			elasticPlugin := plugins.NewElasticPlugin()
			computedConfiguration.Plugins[elasticPlugin.Name()] = elasticPlugin
			auth0Plugin := plugins.NewAuth0Plugin()
			computedConfiguration.Plugins[auth0Plugin.Name()] = auth0Plugin
			minioPlugin := plugins.NewMinioPlugin()
			computedConfiguration.Plugins[minioPlugin.Name()] = minioPlugin
			jaegerPlugin := plugins.NewJaegerPlugin()
			computedConfiguration.Plugins[jaegerPlugin.Name()] = jaegerPlugin

			for _, k8sCluster := range serverYaml.K8s {
				k8sClient, err := getK8sClient(*k8sCluster)
				if err != nil {
					return err
				}
				computedConfiguration.K8sClients[k8sCluster.Name] = k8sClient
			}
			for _, registry := range serverYaml.Docker.Registries {
				computedConfiguration.DockerAuths[registry.Name] = types.AuthConfig{
					Username:      registry.Username,
					Email:         registry.Email,
					Password:      registry.Password,
					ServerAddress: registry.Host,
				}
			}
			for _, daemon := range serverYaml.Docker.Daemons {
				name := daemon.Name
				dockerClient, err := GetDockerClient(*daemon)
				if err != nil {
					return err
				}
				computedConfiguration.DockerClients[name] = dockerClient
			}
			_ = r.GET("/ping", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{
					"message": "OK",
				})
			})
			sshPkDir, _ := filepath.Abs(storageDir)
			os.MkdirAll(sshPkDir, os.ModePerm)
			_ = r.POST("/ssh/:domain", func(c *gin.Context) {
				file, err := c.FormFile("pk")
				if err != nil {
					c.AbortWithStatusJSON(http.StatusBadRequest, errors.Wrapf(err, "Pk part file is required"))
					return
				}
				fullpath := filepath.Join(utils.GetSshDirectory(), c.Param("domain"))
				dest, err := os.Create(fullpath)
				if err != nil {
					c.AbortWithStatusJSON(http.StatusBadRequest, errors.Wrapf(err, "Failed to create file %s", fullpath))
					return
				}
				src, err := file.Open()
				if err != nil {
					c.AbortWithStatusJSON(http.StatusBadRequest, errors.Wrapf(err, "Failed to create open pk file"))
					return
				}
				_, err = io.Copy(dest, src)
				if err != nil {
					c.AbortWithStatusJSON(http.StatusBadRequest, errors.Wrapf(err, "Failed to write contents"))
					return
				}
				c.Status(http.StatusOK)
				c.Done()
			})
			wrapReq := func(r http.HandlerFunc) gin.HandlerFunc {
				return func(c *gin.Context) {
					r(c.Writer, c.Request)
				}
			}
			wrapReq2 := func(r http.Handler) gin.HandlerFunc {
				return func(c *gin.Context) {
					r.ServeHTTP(c.Writer, c.Request)
				}
			}
			r.GET("/debug/pprof/", wrapReq(pprof.Index))
			r.GET("/debug/pprof/cmdline", wrapReq(pprof.Cmdline))
			r.GET("/debug/pprof/profile", wrapReq(pprof.Profile))
			r.GET("/debug/pprof/symbol", wrapReq(pprof.Symbol))
			r.Any("/debug/pprof/goroutine", wrapReq2(pprof.Handler("goroutine")))
			r.Any("/debug/pprof/heap", wrapReq2(pprof.Handler("heap")))
			r.Any("/debug/pprof/threadcreate", wrapReq2(pprof.Handler("threadcreate")))
			r.Any("/debug/pprof/block", wrapReq2(pprof.Handler("block")))
			_ = r.POST("/deploy/teardown", func(c *gin.Context) {
				var err error
				contents, err := readFile(c, "file")
				if err != nil {
					c.AbortWithStatusJSON(http.StatusBadRequest, err)
					return
				}
				appConfig := config.ApplicationYaml{}
				err = yaml.Unmarshal(contents, &appConfig)
				if err != nil {
					c.AbortWithStatusJSON(http.StatusBadRequest, errors.Wrapf(err, "Failed to read yaml"))
					return
				}
				envToDeploy := c.Query("env")
				var configEnv config.Environment
				envFound := false
				for _, env := range appConfig.Environments {
					if env.Name == envToDeploy {
						configEnv = env
						envFound = true
					}
				}
				if !envFound {
					c.JSON(http.StatusNotFound, gin.H{
						"message": fmt.Sprintf("Environment %s not in the yaml", envToDeploy),
					})
					return
				}
				if configEnv.Type != "kubernetes" {
					c.JSON(http.StatusBadRequest, gin.H{
						"message": fmt.Sprintf("Only kubernetes type can be deleted"),
					})
					return
				}
				k8sClient := computedConfiguration.K8sClients[configEnv.Cluster]
				if k8sClient == nil {
					c.JSON(http.StatusNotFound, gin.H{
						"message": fmt.Sprintf("K8s Cluster %s not in the configuration", configEnv.Cluster),
					})
					return
				}
				dockerCli := computedConfiguration.DockerClients[configEnv.Cluster]
				if dockerCli == nil {
					c.JSON(http.StatusNotFound, gin.H{
						"message": fmt.Sprintf("Docker %s not in the configuration", configEnv.Cluster),
					})
					return
				}
				helmClient, err := getHelmClient(k8sClient)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{
						"message": fmt.Sprintf("Failed to initialize helm client %s", err.Error()),
					})
					return
				}
				defer helmClient.Done()
				helmOptions := builders.HelmDeleteOptions{
					Config:      appConfig,
					Client:      helmClient.Client,
					K8sClient:   k8sClient.ClientSet,
					DockerCli:   dockerCli,
					Environment: configEnv,
				}

				response, err := builders.DeleteK8s(helmOptions)
				if err != nil {
					c.AbortWithStatusJSON(http.StatusInternalServerError, err)
					return
				}
				_ = response
				c.Done()

			})
			_ = r.POST("/deploy", func(c *gin.Context) {
				var err error
				contents, err := readFile(c, "file")
				if err != nil {
					c.AbortWithStatusJSON(http.StatusBadRequest, err)
					return
				}
				appConfig := config.ApplicationYaml{}
				err = yaml.Unmarshal(contents, &appConfig)
				if err != nil {
					c.AbortWithStatusJSON(http.StatusBadRequest, errors.Wrapf(err, "Failed to read yaml"))
					return
				}
				envToDeploy := c.Query("env")
				var configEnv config.Environment
				envFound := false
				for _, env := range appConfig.Environments {
					if env.Name == envToDeploy {
						configEnv = env
						envFound = true
					}
				}
				if !envFound {
					c.JSON(http.StatusNotFound, gin.H{
						"message": fmt.Sprintf("Environment %s not in the yaml", envToDeploy),
					})
					return
				}

				tarFormFile, err := c.FormFile(envToDeploy)
				if err == nil {
					tarFile, err := tarFormFile.Open()
					if err != nil {
						c.AbortWithStatusJSON(http.StatusBadRequest, errors.Wrapf(err, "Error opening repository tar"))
						return
					}
					destDir, err := ioutil.TempDir("", "na-k8s-build-git")
					os.TempDir()
					err = archive.Untar(tarFile, destDir, &archive.TarOptions{})
					if err != nil {
						c.AbortWithStatusJSON(http.StatusBadRequest, errors.Wrapf(err, "Error unpacking repository repository tar"))
						return
					}
					configEnv.Repository = destDir
				}
				finalConfig := map[string]interface{}{}

				if err := mergo.Merge(&finalConfig, appConfig.Config); err != nil {
					c.AbortWithStatusJSON(http.StatusBadRequest, errors.Wrapf(err, "Failed to merge finalConfig"))
					return
				}
				if err := mergo.Merge(&finalConfig, configEnv.Config); err != nil {
					c.AbortWithStatusJSON(http.StatusBadRequest, errors.Wrapf(err, "Failed to merge finalConfig"))
					return
				}

				if err := mergo.Merge(&appConfig.Dependencies, configEnv.Dependencies); err != nil {
					c.AbortWithStatusJSON(http.StatusBadRequest, errors.Wrapf(err, "Failed to merge dependencies"))
					return
				}
				for pluginName, value := range appConfig.Dependencies {
					plugin := computedConfiguration.Plugins[pluginName]
					if plugin == nil {
						c.AbortWithStatusJSON(http.StatusBadRequest, errors.Errorf("Plugin %s not supported", pluginName))
						return
					}

					provisionOptions := plugins.ProvisionOptions{
						ServerConfig: serverYaml,
						MinioClient:  s3Client,
						Data:         value,
						Env:          configEnv,
						Yaml:         appConfig,
					}
					provisionResult, err := plugin.Provision(provisionOptions)
					if err != nil {
						c.AbortWithStatusJSON(http.StatusBadRequest, errors.Wrapf(err, "Failed to provision plugin %s", pluginName))
						return
					}
					key := ""
					if plugin.IsPrivate() {
						key = fmt.Sprintf("_%s", pluginName)
					} else {
						key = pluginName
					}
					finalConfig[key] = provisionResult
				}

				configBytes, err := json.Marshal(finalConfig)
				if err != nil {
					c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
						"error": errors.Wrapf(err, "Failed to marshall config data").Error(),
					})
					return
				}
				log.Debugf("Json string %s", string(configBytes))
				configUrl := ""
				// only upload config if it's not empty
				if !reflect.DeepEqual(finalConfig, map[string]interface{}{}) {
					objectName := fmt.Sprintf("%s/%s/config.json", appConfig.App, configEnv.Name)
					_, err = s3Client.PutObject(serverYaml.Minio.Bucket, objectName, bytes.NewReader(configBytes), int64(len(configBytes)), minio.PutObjectOptions{})
					if err := mergo.Merge(&finalConfig, configEnv.Config); err != nil {
						c.AbortWithStatusJSON(http.StatusBadRequest, errors.Wrapf(err, "Failed to upload config to minio"))
						return
					}
					reqParams := make(url.Values)
					presignedUrl, err := s3Client.PresignedGetObject(serverYaml.Minio.Bucket, objectName, time.Hour*24*7, reqParams)
					if err != nil {
						c.AbortWithStatusJSON(http.StatusBadRequest, errors.Wrapf(err, "Failed to get presigned uri for config"))
						return
					}
					configUrl = presignedUrl.String()
					configEnv.EnvVars = append(configEnv.EnvVars, config.EnvironmentVariable{Name: configEnvVariableName, Value: configUrl})
				}
				dockerAuth, ok := computedConfiguration.DockerAuths[configEnv.Cluster]
				if !ok {
					c.AbortWithStatusJSON(http.StatusBadRequest, errors.Errorf("No registry with the cluster name %s", configEnv.Cluster))
				}
				switch strings.ToLower(configEnv.Type) {
				case "docker":
					dockerCli := computedConfiguration.DockerClients[configEnv.Cluster]
					if dockerCli == nil {
						c.JSON(http.StatusNotFound, gin.H{
							"message": fmt.Sprintf("Docker %s not in the configuration", configEnv.Cluster),
						})
						return
					}
					for handlername, handler := range appConfig.Handlers {
						response, err := builders.BuildAndPush(builders.BuildOptions{
							Config:      appConfig,
							Client:      dockerCli,
							Environment: configEnv,
							Handler:     handler,
							Handlername: handlername,
							Auth:        dockerAuth,
						}, c.Writer)
						if err != nil {
							c.JSON(http.StatusBadRequest, gin.H{
								"error": errors.Wrapf(err, "Failed to build handler %s", handlername).Error(),
							})
							return
						}
						containerName := fmt.Sprintf("%s-%s-%s", appConfig.App, configEnv.Name, handlername)
						ctx := context.Background()
						inspect, err := dockerCli.ContainerInspect(ctx, containerName)
						if err == nil {
							log.Printf("Image %s", inspect.Image)
							//if inspect.Config.Image == response.Tag && cmp.Equal(inspect.Config.Cmd, ) {
							//	c.Writer.WriteString(fmt.Sprintf("Skipping handler %s, sha256 has not changed\n", handlername))
							//	continue
							//}
							// container exist
							// delete it
							err = dockerCli.ContainerRemove(ctx, inspect.ID, types.ContainerRemoveOptions{Force: true})
							if err != nil {
								c.JSON(http.StatusBadRequest, gin.H{
									"message": fmt.Sprintf("Failed to remove container %s", containerName),
								})
								return
							}
						}
						dockerOptions, ok := configEnv.HandlerOptions[handlername]
						if err := mergo.Merge(&dockerOptions, handler); err != nil {
							c.JSON(http.StatusInternalServerError, gin.H{
								"error": errors.Wrapf(err, "Failed to merge handler options %s", handlername).Error(),
							})
							return
						}
						var containerConfig container.Config
						var hostConfig container.HostConfig
						var networkConfig network.NetworkingConfig
						if ok {
							if len(dockerOptions.Command) > 0 {
								containerConfig.Cmd = dockerOptions.Command
							}
							if dockerOptions.NetworkMode != "" {
								hostConfig.NetworkMode = container.NetworkMode(dockerOptions.NetworkMode)
							}
							if hostConfig.NetworkMode != "host" {
								hostConfig.PortBindings = nat.PortMap{}
								containerConfig.ExposedPorts = map[nat.Port]struct{}{}
								for hostport, containerport := range dockerOptions.Ports {
									containerportprotocol := nat.Port(fmt.Sprintf("%s/tcp", containerport))
									hostConfig.PortBindings[containerportprotocol] = []nat.PortBinding{
										{
											HostPort: hostport,
										},
									}
									containerConfig.ExposedPorts[containerportprotocol] = struct{}{}
								}
							}

							for volumeName, volumeOpts := range dockerOptions.Volumes {

								parts := strings.Split(volumeOpts.Path, ":")
								if len(parts) == 2 {
									bind := volumeOpts.Path
									hostConfig.Binds = append(hostConfig.Binds, bind)
								} else {
									var vol types.Volume
									volname := fmt.Sprintf("%s-%s-%s-%s", appConfig.App, configEnv.Name, handlername, volumeName)
									vol, err = dockerCli.VolumeInspect(ctx, volname)
									if err != nil {
										vol, err = dockerCli.VolumeCreate(ctx, volume.VolumeCreateBody{Driver: "local", Name: volname})
										if err != nil {
											c.JSON(http.StatusInternalServerError, gin.H{
												"message": fmt.Sprintf("Failed to create volume %s for handler %s", volname, handlername),
											})
											return
										}
									}
									bind := fmt.Sprintf("%s:%s", vol.Mountpoint, volumeOpts.Path)
									hostConfig.Binds = append(hostConfig.Binds, bind)
								}

								containerConfig.Volumes = map[string]struct{}{
									volumeOpts.Path: {},
								}
							}
						}
						for _, env := range append(configEnv.EnvVars, handler.EnvVars...) {
							containerConfig.Env = append(containerConfig.Env, fmt.Sprintf("%s=%s", env.Name, env.Value))
						}
						containerConfig.Image = response.Tag
						hostConfig.RestartPolicy = container.RestartPolicy{Name: "always"}
						cr, err := dockerCli.ContainerCreate(
							ctx,
							&containerConfig,
							&hostConfig,
							&networkConfig,
							containerName,
						)
						if err != nil {
							c.JSON(http.StatusBadRequest, gin.H{
								"error": errors.Wrapf(err, "Failed to create container image=%s container=%s", response.Tag, containerName).Error(),
							})
							return
						}
						err = dockerCli.ContainerStart(ctx, containerName, types.ContainerStartOptions{})
						if err != nil {
							c.JSON(http.StatusBadRequest, gin.H{
								"message": fmt.Sprintf("Failed to start container id=%s image=%s container=%s", cr.ID, response.Tag, containerName),
							})
							return
						}
					}

				case "kubernetes":
					k8sClient := computedConfiguration.K8sClients[configEnv.Cluster]
					if k8sClient == nil {
						c.JSON(http.StatusNotFound, gin.H{
							"message": fmt.Sprintf("K8s Cluster %s not in the configuration", configEnv.Cluster),
						})
						return
					}
					dockerCli := computedConfiguration.DockerClients[configEnv.Cluster]
					if dockerCli == nil {
						c.JSON(http.StatusNotFound, gin.H{
							"message": fmt.Sprintf("Docker %s not in the configuration", configEnv.Cluster),
						})
						return
					}
					helmClient, err := getHelmClient(k8sClient)
					if err != nil {
						c.JSON(http.StatusInternalServerError, gin.H{
							"message": fmt.Sprintf("Failed to initialize helm client %s", err.Error()),
						})
						return
					}
					defer helmClient.Done()
					helmOptions := builders.HelmOptions{
						Pw:          progressbar.NewHttpProgressBar(c.Writer),
						Config:      appConfig,
						Client:      helmClient.Client,
						K8sClient:   k8sClient.ClientSet,
						DockerCli:   dockerCli,
						Environment: configEnv,
						Auth:        dockerAuth,
					}

					response, err := builders.DeployK8s(helmOptions)
					if err != nil {
						c.AbortWithStatusJSON(http.StatusInternalServerError, err)
						return
					}
					_ = response
					c.Done()
				default:
					c.JSON(http.StatusNotFound, gin.H{
						"message": fmt.Sprintf("Deployment type %s not supported for env %s", configEnv.Type, configEnv.Name),
					})
					return
				}

			})
			err = r.Run(fmt.Sprintf("%s:%d", o.Host, o.Port))
			if err != nil {
				return err
			}
			log.Infof("Listening on %s:%d with config %s", o.Host, o.Port, o.Config)
			return nil
		},
	}
	// Here you will define your flags and configuration settings.
	flags := serveCmd.PersistentFlags()
	flags.StringVarP(&o.Config, "config", "c", "", "Path to config")
	flags.Int64VarP(&o.Port, "port", "p", 6200, "Port to listen")
	flags.StringVar(&o.Host, "host", "0.0.0.0", "Host to listen")

	serveCmd.MarkPersistentFlagRequired("config")

	return serveCmd
}

func GetDockerClient(daemon config.DockerDaemon) (*client.Client, error) {
	var funcs []func(client2 *client.Client) error
	var err error
	if daemon.FromEnv {
		funcs = append(funcs, client.FromEnv)
	}
	if !daemon.FromEnv && daemon.Ca != "" && daemon.Cert != "" && daemon.Key != "" {
		ca, err := ConvertToBytes(daemon.Ca)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to read ca")
		}

		certBlock, err := ConvertToBytes(daemon.Cert)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to read cert")
		}
		keyBlock, err := ConvertToBytes(daemon.Key)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to read key")
		}
		// Load CA cert
		cert, err := tls.X509KeyPair(certBlock, keyBlock)

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(ca)

		// Setup HTTPS client
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      caCertPool,
		}
		tlsConfig.BuildNameToCertificate()
		transport := &http.Transport{TLSClientConfig: tlsConfig}
		httpClient := &http.Client{Transport: transport}
		funcs = append(funcs, client.WithHTTPClient(httpClient))
	}
	if daemon.Host != "" {
		funcs = append(funcs, client.WithHost(daemon.Host))
	}

	dockerCli, err := client.NewClientWithOpts(funcs...)
	if err != nil {
		return nil, err
	}
	dockerCli.NegotiateAPIVersion(context.Background())
	return dockerCli, err
}

type K8sClient struct {
	ClientSet *kubernetes.Clientset
	Config    *rest.Config
}

func getK8sClient(k8sCluster config.K8sCluster) (*K8sClient, error) {
	clusterName := k8sCluster.Name
	authInfo := &api.AuthInfo{}
	cluster := &api.Cluster{
		Server: k8sCluster.Url,
	}
	ca, _ := ConvertToBytes(k8sCluster.Ca)
	if k8sCluster.Token == "" {
		key, _ := ConvertToBytes(k8sCluster.Key)
		cert, _ := ConvertToBytes(k8sCluster.Cert)
		authInfo.ClientKeyData = key
		authInfo.ClientCertificateData = cert
		cluster.CertificateAuthorityData = ca
	} else {
		token, _ := ConvertToString(k8sCluster.Token)
		cluster.CertificateAuthorityData = ca
		authInfo.Token = token
	}
	k8sConfig, err := clientcmd.BuildConfigFromKubeconfigGetter("", func() (*api.Config, error) {
		return &api.Config{
			Contexts: map[string]*api.Context{
				clusterName: {
					Cluster:  clusterName,
					AuthInfo: "k8s-user",
				},
			},
			AuthInfos: map[string]*api.AuthInfo{
				"k8s-user": authInfo,
			},
			CurrentContext: clusterName,
			APIVersion:     "v1",
			Kind:           "Container",
			Clusters: map[string]*api.Cluster{
				clusterName: cluster,
			},
		}, nil
	})
	if err != nil {
		return nil, err
	}
	clientSet, err := kubernetes.NewForConfig(k8sConfig)
	if err != nil {
		return nil, err
	}
	return &K8sClient{Config: k8sConfig, ClientSet: clientSet}, nil
}

type HelmClient struct {
	Done   func()
	Client *helm.Client
}

func getHelmClient(client *K8sClient) (*HelmClient, error) {
	k8sClient := client.ClientSet
	k8sConfig := client.Config
	var err error
	helmNamespace := "kube-system"
	var tillerTunnel *kube.Tunnel
	tillerTunnel, err = portforwarder.New(helmNamespace, k8sClient, k8sConfig)
	if err != nil {
		saHelm := "helm-admin"
		serviceAccountInterface := k8sClient.CoreV1().ServiceAccounts(helmNamespace)
		sa, err := serviceAccountInterface.Get(saHelm, metav1.GetOptions{})
		if err != nil {

			autoMountSa := true
			sa, err = serviceAccountInterface.Create(&corev1.ServiceAccount{
				AutomountServiceAccountToken: &autoMountSa,
				ObjectMeta: metav1.ObjectMeta{
					Name:      saHelm,
					Namespace: helmNamespace,
				},
			})
			if err != nil {
				return nil, err
			}
			_, err := k8sClient.RbacV1().ClusterRoleBindings().Create(&rbac_v1.ClusterRoleBinding{
				RoleRef: rbac_v1.RoleRef{
					Name:     "cluster-admin",
					Kind:     "ClusterRole",
					APIGroup: rbac_v1.GroupName,
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: saHelm,
				},
				Subjects: []rbac_v1.Subject{
					{
						Name:      saHelm,
						Namespace: helmNamespace,
						Kind:      rbac_v1.ServiceAccountKind,
					},
				},
			})
			if err != nil {
				return nil, err
			}
		}
		log.Printf("Using service account %s for helm", sa.Name)

		// helm is not installed
		err = installer.Install(k8sClient, &installer.Options{
			Namespace:      helmNamespace,
			ServiceAccount: sa.Name,
			ForceUpgrade:   true,
			ImageSpec:      "gcr.io/kubernetes-helm/tiller:v2.9.1",
		})
		if err != nil {
			return nil, err
		}
		timeout := 20 * time.Second
		deadline := time.Now().Add(timeout)
		for {
			tillerTunnel, err = portforwarder.New(helmNamespace, k8sClient, k8sConfig)
			if err == nil {
				break
			}
			if time.Now().After(deadline) {
				return nil, errors.New(fmt.Sprintf("Helm tiller is not ready after %s", timeout))
			}
		}
		tillerTunnel, err = portforwarder.New(helmNamespace, k8sClient, k8sConfig)
		if err != nil {
			return nil, err
		}
	}
	tillerTunnelAddress := fmt.Sprintf("localhost:%d", tillerTunnel.Local)
	helmClient := helm.NewClient(helm.Host(tillerTunnelAddress))

	return &HelmClient{
		Client: helmClient,
		Done: func() {
			tillerTunnel.Close()
		},
	}, nil
}

func ConvertToString(input string) (string, error) {
	var ca string
	var err error
	if filepath.IsAbs(input) {
		var tmp []byte
		tmp, err = ioutil.ReadFile(input)
		ca = string(tmp)
	} else {
		ca = input
	}
	if err != nil {
		return "", err
	}
	return ca, nil
}
func ConvertToBytes(input string) ([]byte, error) {
	var ca []byte
	var err error
	if filepath.IsAbs(input) {
		ca, err = ioutil.ReadFile(input)
	} else {
		ca = []byte(input)
	}
	if err != nil {
		return nil, err
	}
	return ca, nil
}
