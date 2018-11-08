# Managed deploy on K8s and Docker

## Requirements

The only requirement is a S3 Server (e.g Minio) because configuration of the app is pushed to a json file.

## Plugins

In order to reuse the configuration we have plugins that add values to the final json config.

## Example config
```yaml
docker:
  registries:
  - name: prod
    host: docker.mydomain.com
    username: <USER>
    password: <PASSWORD>
  daemons:
  - name: prod
    host: "tcp://192.168.1.3:2376"

k8s:
- name: prod
  url: "https://192.168.1.3:6443"
  ca: |
    PEM_CERTIFICATE
  token: "<JWT_TOKEN>"


minio:
  endpoint: string
  accesskey: string
  secretkey: string
  bucket: string
  ssl: boolean


postgresql:
  database: string
  host: string
  user: string
  password: string
  port: number

auth0:
  token: <JWT_ADMIN_TOKEN>
  url: https://mydomain.auth0.com/api/v2


redis:
  host: string
  port: number
  password: string



elasticsearch:
  host: string
  port: string

jaeger:
  host: string
  port: number
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
    repository: git@github.com:Dviejopomata/easy-cdn.git#master
    type: Kubernetes
    domain: easy-cdn.example.com
    cluster: animal
    config: {}
    env_variables: [[]

```
