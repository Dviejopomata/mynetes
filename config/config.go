package config

import (
	"github.com/docker/docker/api/types/container"
	"github.com/docker/go-connections/nat"
)

type K8sCluster struct {
	Name  string
	Url   string
	Ca    string
	Cert  string
	Key   string
	Token string
}
type DockerRegistry struct {
	Name     string
	Email    string
	Username string
	Password string
	Host     string
}
type DockerDaemon struct {
	Name    string
	Host    string
	FromEnv bool
	Ca      string
	Cert    string
	Key     string
}
type DockerConfig struct {
	Daemons    []*DockerDaemon   `yaml:"daemons"`
	Registries []*DockerRegistry `yaml:"registries"`
}
type MinioConfig struct {
	Endpoint  string `yaml:"endpoint"`
	Accesskey string `yaml:"accessKey"`
	Secretkey string `yaml:"secretKey"`
	Bucket    string `yaml:"bucket"`
	Ssl       bool   `yaml:"ssl"`
}
type ServerYaml struct {
	K8s           []*K8sCluster       `yaml:"k8s"`
	Docker        DockerConfig        `yaml:"docker"`
	Minio         MinioConfig         `yaml:"minio"`
	Postgresql    PostgresqlConfig    `yaml:"postgresql"`
	Redis         RedisConfig         `yaml:"redis"`
	Auth0         Auth0Config         `yaml:"auth0"`
	Elasticsearch ElasticsearchConfig `yaml:"elasticsearch"`
	Jaeger        JaegerConfig        `yaml:"jaeger"`
}
type ElasticsearchConfig struct {
	Host string `yaml:"host"`
	Port int64  `yaml:"port"`
}

type JaegerConfig struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
}

type Auth0Config struct {
	Token string `yaml:"token"`
	Url   string `yaml:"url"`
}
type RedisConfig struct {
	Host     string `yaml:"host"`
	Port     int64  `yaml:"port"`
	Password string `yaml:"password"`
}

type PostgresqlConfig struct {
	Host     string                `yaml:"host"`
	Port     int64                 `yaml:"port"`
	User     string                `yaml:"user"`
	Password string                `yaml:"password"`
	Database string                `yaml:"database"`
	Slaves   []PostgresSlaveConfig `yaml:"slaves"`
}
type PostgresSlaveConfig struct {
	Host string `yaml:"host"`
	Port int64  `yaml:"port"`
}

type Handler struct {
	NetworkMode string                  `yaml:"network_mode"`
	File        string                  `yaml:"file,omitempty"`
	Domain      string                  `yaml:"domain,omitempty"`
	Domains     []string                `yaml:"domains,omitempty"`
	MetricsPath string                  `yaml:"metrics_path,omitempty"`
	URL         string                  `yaml:"url,omitempty"`
	Liveness    *string                 `yaml:"liveness,omitempty"`
	Rewrite     string                  `yaml:"strip_path"`
	Ports       map[string]string       `yaml:"ports"`
	Command     []string                `yaml:"command"`
	Volumes     map[string]VolumeConfig `yaml:"volumes"`
	EnvVars     []EnvironmentVariable   `yaml:"env_variables,omitempty"`
}
type VolumeConfig struct {
	Path string `yaml:"path"`
}

type EnvironmentVariable struct {
	Name  string
	Value string
}
type Environment struct {
	Name           string                            `yaml:"name,omitempty"`
	Domain         string                            `yaml:"domain,omitempty"`
	Repository     string                            `yaml:"repository,omitempty"`
	Config         map[string]interface{}            `yaml:"config,omitempty"`
	EnvVars        []EnvironmentVariable             `yaml:"env_variables,omitempty"`
	Cluster        string                            `yaml:"cluster,omitempty"`
	Type           string                            `yaml:"type,omitempty"`
	HandlerOptions map[string]Handler                `yaml:"options"`
	Dependencies   map[string]map[string]interface{} `yaml:"dependencies"`
}

type HostConfig struct {
	Ports       nat.PortMap           `yaml:"ports"`
	NetworkMode container.NetworkMode `yaml:"network_mode"`
}

type ApplicationYaml struct {
	App    string `yaml:"app,omitempty"`
	Config map[string]interface{}
	Docker struct {
		Registry struct {
			URL      string `yaml:"url,omitempty"`
			User     string `yaml:"user,omitempty"`
			Password string `yaml:"password,omitempty"`
		} `yaml:"registry,omitempty"`
	} `yaml:"docker,omitempty"`
	Dependencies map[string]map[string]interface{} `yaml:"dependencies"`
	Handlers     map[string]Handler                `yaml:"handlers"`
	Environments []Environment                     `yaml:"environments"`
}
