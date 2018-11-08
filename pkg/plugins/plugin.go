package plugins

import (
	"github.com/minio/minio-go"
	"github.com/Dviejopomata/mynetes/config"
)

type ProvisionOptions struct {
	Yaml         config.ApplicationYaml
	Env          config.Environment
	ServerConfig config.ServerYaml
	Data         map[string]interface{}
	MinioClient  *minio.Client
}

type Plugin interface {
	Provision(options ProvisionOptions) (interface{}, error)
	Name() string
	IsPrivate() bool
}
