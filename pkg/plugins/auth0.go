package plugins

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/minio/minio-go"
	"github.com/pkg/errors"
	"gitlab.nextagilesoft.com/saas2/core/log"
	"io/ioutil"
	"net/http"
)

type auth0Plugin struct {
}

type Auth0Options struct {
	Description  string   `json:"description"`
	CallbackUrls []string `json:"callback_urls"`
}
type Auth0ResponseOptions struct {
	ClientId     string `json:"client_id"`
	Domain       string `json:"domain"`
	ClientSecret string `json:"_client_secret"`
}

func mapToAuth0Options(data map[string]interface{}) (Auth0Options, error) {
	byteData, err := json.Marshal(data)
	if err != nil {
		return Auth0Options{}, err
	}
	pgOptions := Auth0Options{}
	err = json.Unmarshal(byteData, &pgOptions)
	if err != nil {
		return Auth0Options{}, err
	}
	return pgOptions, nil
}
func (p auth0Plugin) createClient(o ProvisionOptions) (map[string]interface{}, error) {
	authConfig := o.ServerConfig.Auth0
	auth0Options, err := mapToAuth0Options(o.Data)
	body := map[string]interface{}{
		"name":        fmt.Sprintf("%s-%s", o.Yaml.App, o.Env.Name),
		"description": auth0Options.Description,
		//"logo_uri":                   "",
		"callbacks": auth0Options.CallbackUrls,
		//"allowed_origins":            []string{},
		//"web_origins":                []string{},
		//"client_aliases":             []string{},
		//"allowed_clients":            []string{},
		//"allowed_logout_urls":        []string{},
		//"grant_types":                []string{},
		"is_first_party":             true,
		"token_endpoint_auth_method": "client_secret_post",
		"app_type":                   "regular_web",
		"jwt_configuration": map[string]interface{}{
			"alg": "RS256",
			"lifetime_in_seconds": 36000,
		},
		"oidc_conformant": true,
		//"sso":                        false,
		//"cross_origin_auth":          false,
		//"cross_origin_loc":           "",
		//"sso_disabled":               false,
		//"custom_login_page_on":       false,
		//"custom_login_page":          "",
		//"custom_login_page_preview":  "",
		//"form_template":              "",
		//"is_heroku_app":              false,
	}
	httpClient := http.Client{}
	contents, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	request, err := http.NewRequest("POST", fmt.Sprintf("%s/clients", authConfig.Url), bytes.NewReader(contents))
	if err != nil {
		return nil, err
	}
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", authConfig.Token))
	request.Header.Add("content-type", "application/json")
	response, err := httpClient.Do(request)
	if err != nil {
		return nil, err
	}

	responseContents, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	data := map[string]interface{}{}
	err = json.Unmarshal(responseContents, &data)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusCreated {
		log.Infof("Response %v", data)
		return data, errors.Errorf("Api responded statuscode %d", response.StatusCode)
	}
	return data, err
}

func mapInterfaceToAuthResponse(data map[string]interface{}) Auth0ResponseOptions {
	tenant := data["tenant"].(string)
	return Auth0ResponseOptions{
		ClientId:     data["client_id"].(string),
		Domain:       fmt.Sprintf("%s.auth0.com", tenant),
		ClientSecret: data["client_id"].(string),
	}
}
func (auth0Plugin) IsPrivate() bool {
	return false
}
func (p auth0Plugin) Provision(o ProvisionOptions) (interface{}, error) {

	yaml := o.Yaml
	env := o.Env
	serverConfig := o.ServerConfig
	minioClient := o.MinioClient
	authConfig := o.ServerConfig.Auth0
	objectName := fmt.Sprintf("%s/%s/%s.json", yaml.App, env.Name, p.Name())
	objectInfo, err := minioClient.StatObject(serverConfig.Minio.Bucket, objectName, minio.StatObjectOptions{})
	if err == nil {
		// object exists
		// update client
		object, err := minioClient.GetObject(o.ServerConfig.Minio.Bucket, objectInfo.Key, minio.GetObjectOptions{})
		if err != nil {
			return nil, err
		}
		contents, err := ioutil.ReadAll(object)
		authResponse := Auth0ResponseOptions{}
		err = json.Unmarshal(contents, &authResponse)
		if err != nil {
			return nil, err
		}

		httpClient := http.Client{}
		request, err := http.NewRequest("GET", fmt.Sprintf("%s/clients/%s", authConfig.Url, authResponse.ClientId), bytes.NewReader(contents))
		if err != nil {
			return nil, err
		}
		request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", authConfig.Token))
		response, err := httpClient.Do(request)
		if err != nil {
			return nil, err
		}

		responseContents, err := ioutil.ReadAll(response.Body)
		if err != nil {
			return nil, err
		}

		data := map[string]interface{}{}
		err = json.Unmarshal(responseContents, &data)
		if err != nil {
			return nil, err
		}

		return mapInterfaceToAuthResponse(data), nil

	} else {
		client, err := p.createClient(o)
		if err != nil {
			log.Debugf("Returned %v", client)
			return nil, err
		}
		jsonBytes, err := json.Marshal(client)
		if err != nil {
			return nil, err
		}
		_, err = minioClient.PutObject(serverConfig.Minio.Bucket, objectName, bytes.NewReader(jsonBytes), int64(len(jsonBytes)), minio.PutObjectOptions{})
		if err != nil {
			return nil, err
		}
		return mapInterfaceToAuthResponse(client), nil
	}

}

func (auth0Plugin) Name() string {
	return "auth0"
}

func NewAuth0Plugin() auth0Plugin {
	return auth0Plugin{}
}
