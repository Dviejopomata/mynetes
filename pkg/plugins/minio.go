package plugins

type minioPlugin struct {
}

func (minioPlugin) IsPrivate() bool {
	return true
}

type minioResponseOptions struct {
	Endpoint  string `json:"endpoint"`
	Accesskey string `json:"accessKey"`
	Secretkey string `json:"secretKey"`
	Bucket    string `json:"bucket"`
	Ssl       bool   `json:"ssl"`
}

func (minioPlugin) Provision(options ProvisionOptions) (interface{}, error) {
	return minioResponseOptions{
		Bucket:    options.ServerConfig.Minio.Bucket,
		Accesskey: options.ServerConfig.Minio.Accesskey,
		Secretkey: options.ServerConfig.Minio.Secretkey,
		Ssl:       options.ServerConfig.Minio.Ssl,
		Endpoint:  options.ServerConfig.Minio.Endpoint,
	}, nil
}

func (minioPlugin) Name() string {
	return "minio"
}


func NewMinioPlugin() minioPlugin {
	return minioPlugin{}
}