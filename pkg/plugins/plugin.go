package plugins

import (
	"github.com/minio/minio-go"
	"gitlab.nextagilesoft.com/saas2/core/config"
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
