WaTTS MyProxy SSH Plugin
========================

deployment scheme
-----------------

WaTTS:
 - `wattsPluginMyproxySSH` (binary)


Certificate retrieval server:
 - `remote/getCert` (ssh triggered)


Packaging
---------

Use [indigo-dc/watts-plugin-packager](https://github.com/indigo-dc/watts-plugin-packager) to build Debian / RPM / ArchLinux packages:

```
 $ ./makepkg.sh https://github.com/watts-kit/watts_plugin_myproxy_ssh/raw/master/pkg/config.json
```
