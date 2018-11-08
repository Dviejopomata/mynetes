package plugins

type jaegerPlugin struct {
}

func (jaegerPlugin) IsPrivate() bool {
	return true
}

type jaegerResponseOptions struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

func (jaegerPlugin) Provision(options ProvisionOptions) (interface{}, error) {
	return jaegerResponseOptions{
		Host:    options.ServerConfig.Jaeger.Host,
		Port:    options.ServerConfig.Jaeger.Port,
	}, nil
}

func (jaegerPlugin) Name() string {
	return "jaeger"
}

func NewJaegerPlugin() jaegerPlugin {
	return jaegerPlugin{}
}
