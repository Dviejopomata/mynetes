package plugins

type redisPlugin struct {
}

type redisPluginresponse struct {
	Host     string `json:"host"`
	Port     int64  `json:"port"`
	Password string `json:"password"`
}

func (redisPlugin) Provision(options ProvisionOptions) (interface{}, error) {
	return redisPluginresponse{
		Host:     options.ServerConfig.Redis.Host,
		Port:     options.ServerConfig.Redis.Port,
		Password: options.ServerConfig.Redis.Password,
	}, nil
}
func (redisPlugin) IsPrivate() bool {
	return true
}
func (redisPlugin) Name() string {
	return "redis"
}

func NewRedisPlugin() (*redisPlugin) {
	return &redisPlugin{}
}
