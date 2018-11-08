# Managed deploy on K8s and Docker

## R1
```bash

```

## Requirements of the token in kubernetes

### If helm is not installed, it will be installed, so create a token like this

```bash
kubectl create sa -n kube-system helm-admin
kubectl create clusterrolebinding helm-admin --clusterrole=cluster-admin --serviceaccount=kube-system:helm-admin
```


## Example deploy

```yaml
app: cdn

config: {}

handlers:
  api:
    file: Dockerfile
    url: /
    liveness: /

environments:
  - name: prod
    repository: git@gitlab.nextagilesoft.com:gt/static-fs.git#master
    type: Docker
    docker_options:
      api:
        ports:
          7000: 80
    cluster: animal
    config: {}
    env_variables: [[]

```

```shell
http -f POST http://localhost:6200/deploy?env=prod file@./app.yaml
```