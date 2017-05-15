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
				Name:    "foo",
				Type:    "string",
				Default: "bar",
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
