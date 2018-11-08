package plugins


type elasticSearchPlugin struct {
}

type elasticSearchPluginresponse struct {
	Host     string `json:"host"`
	Port     int64  `json:"port"`
}

func (elasticSearchPlugin) Provision(options ProvisionOptions) (interface{}, error) {
	return elasticSearchPluginresponse{
		Host:     options.ServerConfig.Elasticsearch.Host,
		Port:     options.ServerConfig.Elasticsearch.Port,
	}, nil
}
func (elasticSearchPlugin) IsPrivate() bool {
	return true
}
func (elasticSearchPlugin) Name() string {
	return "elasticsearch"
}

func NewElasticPlugin() (*elasticSearchPlugin) {
	return &elasticSearchPlugin{}
}
