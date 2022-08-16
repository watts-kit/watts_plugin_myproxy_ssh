WaTTS MyProxy SSH Plugin
========================

## Build:

```
docker run -it --rm -v /home:/home/ build-oidc-agent-debian:buster /bin/bash
apt-get install golang
cd /home/marcus/projects/watts/watts_plugin_myproxy_ssh
go build
cd remote/getCert
go build
```

## Deploy

```
cd /home/marcus/projects/watts/watts_plugin_myproxy_ssh
scp     remote/getCert/getCert  watts_plugin_myproxy_ssh \
    root@virt3.data.kit.edu:/home/synced_in_cluster/private-configdata/watts/watts_plugin_myproxy_ssh/
ssh root@virt3.data.kit.edu "chown unison:unison /home/synced_in_cluster/private-configdata/watts/watts_plugin_myproxy_ssh/*"
```
