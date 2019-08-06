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

package deploy

import (
	"bytes"
	"fmt"
	"github.com/docker/docker/builder/dockerignore"
	"github.com/docker/docker/pkg/archive"
	errors2 "github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/Dviejopomata/mynetes/config"
	"gopkg.in/yaml.v2"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
)

func GetExcludeByPath(path string) ([]string, error) {
	files := []string{".dockerignore", ".gitignore"}
	var excludeFiles []string
	for _, file := range files {
		f, err := os.Open(filepath.Join(path, file))
		if err != nil {
			continue
		}
		strings, err := dockerignore.ReadAll(f)
		if err != nil {
			return nil, err
		}
		excludeFiles = append(excludeFiles, strings...)
	}
	excludeFiles = append(excludeFiles, ".git", "node_modules", "vendor")
	return excludeFiles, nil
}

func newfileUploadRequest(uri string, params map[string]string, fileParams map[string]io.ReadCloser) (*http.Request, error) {

	var err error
	body := &bytes.Buffer{}
	w := multipart.NewWriter(body)
	for key, r := range fileParams {
		var fw io.Writer

		// Add an image file
		if x, ok := r.(*os.File); ok {
			if fw, err = w.CreateFormFile(key, x.Name()); err != nil {
				return nil, err
			}
		} else {
			// Add other fields
			if fw, err = w.CreateFormFile(key, key); err != nil {
				return nil, err
			}
		}
		if _, err = io.Copy(fw, r); err != nil {
			return nil, err
		}
		if x, ok := r.(io.Closer); ok {
			x.Close()
		}
	}
	for key, val := range params {
		_ = w.WriteField(key, val)
	}
	err = w.Close()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", uri, body)
	req.Header.Set("Content-Type", w.FormDataContentType())
	return req, err
}

func TarFolder(folder string) (io.ReadCloser, error) {
	excludedPatterns, err := GetExcludeByPath(folder)
	if err != nil {
		return nil, err
	}
	file, err := archive.TarWithOptions(folder, &archive.TarOptions{
		ExcludePatterns: excludedPatterns,
	})
	if err != nil {
		return nil, err
	}
	return file, nil
}

// deployCmd represents the deploy command
type Options struct {
	DeployUri  string
	Env        string
	Config     string
	DynamicEnv bool
}

func NewDeployCmd() *cobra.Command {
	o := &Options{}
	var deployCmd = &cobra.Command{
		Use:   "deploy",
		Short: "A brief description of your command",
		Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			var err error
			appConfig := config.ApplicationYaml{}
			contents, err := ioutil.ReadFile(o.Config)
			if err != nil {
				return err
			}
			err = yaml.Unmarshal(contents, &appConfig)
			if err != nil {
				return err
			}
			for _, environment := range appConfig.Environments {
				if environment.Name != o.Env {
					continue
				}
				cfgFile, err := os.Open(o.Config)
				if err != nil {
					return err
				}
				uri := fmt.Sprintf("%s/deploy?env=%s", o.DeployUri, environment.Name)

				files := map[string]io.ReadCloser{
					"file": cfgFile,
				}
				if filepath.IsAbs(environment.Repository) {
					file, err := TarFolder(environment.Repository)
					if err != nil {
						return err
					}
					files[o.Env] = file
				}

				req, err := newfileUploadRequest(uri, map[string]string{}, files)
				if err != nil {
					return err
				}
				client := &http.Client{}
				resp, err := client.Do(req)
				if err != nil {
					return err
				}
				io.Copy(os.Stdout, resp.Body)
				if resp.StatusCode != http.StatusOK {
					return errors2.Errorf("Failed with status code %d", resp.StatusCode)
				}
				//var s *spinner.Spinner
				//rd := bufio.NewReader(resp.Body)
				//for {
				//	line, err := rd.ReadString('\n')
				//	if err != nil {
				//		if err == io.EOF {
				//			break
				//		}
				//		log.Fatalf("read file line error: %v", err)
				//		return err
				//	}
				//	//log.Println(line)
				//	msg := &progressbar.Message{}
				//	err = json.Unmarshal([]byte(line), msg)
				//	if err != nil {
				//		log.Fatalf("Error %v", err)
				//	} else {
				//		if !msg.Done {
				//			s = spinner.New(spinner.CharSets[2], 100*time.Millisecond) // Build our new spinner
				//			s.FinalMSG = fmt.Sprintf("%s\n", msg.Message)
				//			s.Suffix = msg.Message
				//			s.Color("red") // Set the spinner color to red
				//			s.Start()      // Start the spinner
				//		} else {
				//			s.Stop()
				//		}
				//		//os.Stdout.WriteString(fmt.Sprintf("MSG=%s DONE=%v\n", msg.Message, msg.Done))
				//	}
				//
				//}
				return nil
			}

			return errors2.Errorf("No env %s in app.yaml", o.Env)
		},
	}
	persistentFlags := deployCmd.PersistentFlags()
	persistentFlags.StringVar(&o.DeployUri, "deploy-uri", "http://192.168.1.8:7005", "Url to deploy")
	persistentFlags.StringVar(&o.Env, "env", "", "Environment to deploy")
	persistentFlags.StringVarP(&o.Config, "config", "c", "", "A help for foo")
	persistentFlags.BoolVar(&o.DynamicEnv, "dynamic-env", false, "Create the environment if not exists")
	deployCmd.MarkPersistentFlagRequired("config")
	deployCmd.MarkPersistentFlagRequired("env")
	return deployCmd
}
