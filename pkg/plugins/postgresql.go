package plugins

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/Dviejopomata/mynetes/config"
	"github.com/Dviejopomata/mynetes/log"
	_ "github.com/lib/pq"
	"github.com/minio/minio-go"
	"github.com/pkg/errors"
	"github.com/sethvargo/go-password/password"
	"io/ioutil"
	"strings"
)

type postgresqlPlugin struct {
	Db *sql.DB
}

type PostgresqlPluginResponse struct {
	Host     string `json:"host"`
	Port     int64  `json:"port"`
	Database string `json:"database"`
	User     string `json:"user"`
	Password string `json:"password"`
}
type PostgresqlOptions struct {
	Version    float64
	Extensions []string
}

func (postgresqlPlugin) IsPrivate() bool {
	return true
}
func mapToStruct(data map[string]interface{}) (PostgresqlOptions, error) {
	byteData, err := json.Marshal(data)
	if err != nil {
		return PostgresqlOptions{}, err
	}
	pgOptions := PostgresqlOptions{}
	err = json.Unmarshal(byteData, &pgOptions)
	if err != nil {
		return PostgresqlOptions{}, err
	}
	return pgOptions, nil
}

func (p postgresqlPlugin) Provision(o ProvisionOptions) (interface{}, error) {
	//yaml config.ApplicationYaml, env config.Environment, serverConfig config.ServerYaml, data map[string]interface{}
	var err error
	yaml := o.Yaml
	env := o.Env
	serverConfig := o.ServerConfig
	data := o.Data
	minioClient := o.MinioClient
	objectName := fmt.Sprintf("%s/%s/%s.json", yaml.App, env.Name, p.Name())
	objectInfo, err := minioClient.StatObject(o.ServerConfig.Minio.Bucket, objectName, minio.StatObjectOptions{})
	if err == nil {
		object, err := minioClient.GetObject(o.ServerConfig.Minio.Bucket, objectInfo.Key, minio.GetObjectOptions{})
		if err != nil {
			return nil, err
		}
		contents, err := ioutil.ReadAll(object)
		response := PostgresqlPluginResponse{}
		err = json.Unmarshal(contents, &response)
		if err != nil {
			return nil, err
		}
		return response, nil
	}
	db := p.Db

	pgOptions, err := mapToStruct(data)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to transform interface %v to Postgresql options", data)
	}
	log.Infof("Provisioning postgresql instance with version %d", pgOptions.Version)
	postgresPwd, err := password.Generate(32, 10, 10, false, false)
	if err != nil {
		return nil, err
	}
	envName := strings.Replace(env.Name, "-", "_", -1)
	databaseName := fmt.Sprintf("%s_%s", yaml.App, envName)
	options := PostgresqlPluginResponse{
		Database: databaseName,
		User:     databaseName,
		Password: postgresPwd,
	}
	checkDbExists := "SELECT datname FROM pg_catalog.pg_database WHERE lower(datname) = $1;"
	rows, err := db.Query(checkDbExists, strings.ToLower(options.Database))
	if rows.Err() != nil {
		return nil, rows.Err()
	}
	if !rows.Next() {
		// database doesnt exist
		createDbSql := fmt.Sprintf("CREATE DATABASE %s", options.Database)
		_, err = db.Query(createDbSql)
		if err != nil && !strings.Contains(err.Error(), "already exists") {
			return nil, err
		}
	}

	const checkUserExists = `SELECT 1 FROM pg_roles WHERE rolname=$1;`
	userRows, err := db.Query(checkUserExists, options.User)
	if userRows.Err() != nil {
		return nil, userRows.Err()
	}
	if !userRows.Next() {
		// user doesnt exist
		createUserSql := fmt.Sprintf("CREATE USER %s WITH ENCRYPTED PASSWORD '%s';", options.User, options.Password)
		_, err = db.Query(createUserSql)
		if err != nil && !strings.Contains(err.Error(), "already exists") {
			return nil, err
		}
	}

	grantUserDatabase := fmt.Sprintf("GRANT ALL PRIVILEGES ON DATABASE %s TO %s;", options.Database, options.User)
	_, err = db.Query(grantUserDatabase)
	response := PostgresqlPluginResponse{
		Host:     serverConfig.Postgresql.Host,
		Port:     serverConfig.Postgresql.Port,
		Database: options.Database,
		Password: options.Password,
		User:     options.User,
	}
	contents, err := json.Marshal(response)
	if err != nil {
		return nil, err
	}
	for _, extension := range pgOptions.Extensions {
		createExtensionSql := fmt.Sprintf("CREATE EXTENSION IF NOT EXISTS %s;", extension)
		_, err = db.Query(createExtensionSql)
		if err != nil {
			return nil, err
		}
	}
	_, err = minioClient.PutObject(o.ServerConfig.Minio.Bucket, objectName, bytes.NewReader(contents), int64(len(contents)), minio.PutObjectOptions{})
	if err != nil {
		return nil, err
	}
	return response, nil
}
func (postgresqlPlugin) Name() string {
	return "postgresql"
}

func NewPostgresqlPlugin(yaml config.ServerYaml) (*postgresqlPlugin, error) {
	pgConfig := yaml.Postgresql
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable", pgConfig.Host, pgConfig.Port, pgConfig.User, pgConfig.Password, pgConfig.Database)
	db, err := sql.Open("postgres", psqlInfo)

	if err != nil {
		return nil, err
	}
	err = db.Ping()
	if err != nil {
		return nil, err
	}
	return &postgresqlPlugin{Db: db}, nil
}
