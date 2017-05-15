package main

import (
	l "git.scc.kit.edu/lukasburgey/wattsPluginLib"
)

// do not return a plain output yourself.
// use PluginGoodRequest, PluginError, PluginAdditionalLogin instead
func request(plugin l.Plugin) l.Output {
	// exemplarily plugin input access
	foo := plugin.PluginInput.AccessToken

	// exemplarily error
	if foo == "bar" {
		return l.PluginError("revoke failed")
	}

	// exemplarily additional login
	additionalLoginRequirred := false
	if additionalLoginRequirred {
		return l.PluginAdditionalLogin("<provider id>", "<user msg>")
	}

	// do the request that yields a credential
	credential := []l.Credential{
		l.Credential{
			Name:  "foo",
			Type:  "string",
			Value: "bar",
		},
	}
	credentialState := "registerred"
	return l.PluginGoodRequest(credential, credentialState)
}

func revoke(plugin l.Plugin) l.Output {
	// exemplarily error
	err := false
	if err {
		return l.PluginError("revoke failed")
	}
	return l.PluginGoodRevoke()
}

func main() {
	pluginDescriptor := l.PluginDescriptor{
		Version:       "0.1.0",
		Author:        "Lukas Burgey @ KIT within the INDIGO DataCloud Project",
		ActionRequest: request,
		ActionRevoke:  revoke,
		ConfigParams: []l.ConfigParamsDescriptor{
			l.ConfigParamsDescriptor{
				Name:    "myproxy_server",
				Type:    "string",
				Default: "master.data.kit.edu",
			},
			l.ConfigParamsDescriptor{
				Name:    "myproxy_server_pwd",
				Type:    "string",
				Default: "",
			},
			l.ConfigParamsDescriptor{
				Name:    "script_path",
				Type:    "string",
				Default: "./ssh_trigger.py",
			},
			l.ConfigParamsDescriptor{
				Name:    "remote_script",
				Type:    "string",
				Default: "./myproxy_ssh_vm.py",
			},
			l.ConfigParamsDescriptor{
				Name:    "host",
				Type:    "string",
				Default: "watts-x509.data.kit.edu",
			},
			l.ConfigParamsDescriptor{
				Name:    "user",
				Type:    "string",
				Default: "x509",
			},
			l.ConfigParamsDescriptor{
				Name:    "work_dir",
				Type:    "string",
				Default: "/tmp",
			},
		},
		RequestParams: []l.RequestParamsDescriptor{
			l.RequestParamsDescriptor{
				Key:         "pub_key",
				Name:        "public key",
				Description: "the public key of the service",
				Type:        "textarea",
				Mandatory:   false,
			},
		},
	}
	l.PluginRun(pluginDescriptor)
}
