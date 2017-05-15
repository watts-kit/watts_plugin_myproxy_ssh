package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	l "git.scc.kit.edu/lukasburgey/wattsPluginLib"
	"golang.org/x/crypto/ssh"
	mrand "math/rand"
	"time"
)

const (
	letterBytes   = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits
)

// http://stackoverflow.com/questions/22892120/how-to-generate-a-random-string-of-a-fixed-length-in-golang
func randStringBytesMaskImprSrc(n int) []byte {
	var src = mrand.NewSource(time.Now().UnixNano())
	b := make([]byte, n)
	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return b
}

func generateKey() (privateKey string, publicKey string, password string) {
	bits := 4096
	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, bits)
	l.Check(err, 1, "rsa private key generation")

	pkcs1 := x509.MarshalPKCS1PrivateKey(rsaPrivateKey)
	passwordBytes := randStringBytesMaskImprSrc(16)
	encryptedPemBlock, err := x509.EncryptPEMBlock(
		rand.Reader, "RSA PRIVAT KEY", pkcs1, passwordBytes, x509.PEMCipherAES256)
	l.Check(err, 1, "encrypting pem block")

	sshPublicKey, err := ssh.NewPublicKey(&rsaPrivateKey.PublicKey)
	l.Check(err, 1, "ssh public key generation")

	privateKey = string(pem.EncodeToMemory(encryptedPemBlock))
	publicKey = string(ssh.MarshalAuthorizedKey(sshPublicKey))
	password = string(passwordBytes)
	return
}

func request(plugin l.Plugin) l.Output {
	if _, ok := plugin.PluginInput.Params["pub_key"]; ok {
		return l.PluginError("provided key not implemented")
	} else {
		privateKey, publicKey, password := generateKey()

		credential := []l.Credential{
			l.Credential{Name: "private key", Type: "string", Value: privateKey},
			l.Credential{Name: "public key", Type: "string", Value: publicKey},
			l.Credential{Name: "password", Type: "string", Value: password},
		}
		credentialState := "registerred"
		return l.PluginGoodRequest(credential, credentialState)
	}
}

func revoke(plugin l.Plugin) l.Output {
	return l.PluginError("revoke not implemented")
}

func main() {
	pluginDescriptor := l.PluginDescriptor{
		Version:       "0.1.0",
		Author:        "Lukas Burgey @ KIT within the INDIGO DataCloud Project",
		ActionRequest: request,
		ActionRevoke:  revoke,
		ConfigParams: []l.ConfigParamsDescriptor{
			l.ConfigParamsDescriptor{Name: "myproxy_server", Type: "string", Default: "master.data.kit.edu"},
			l.ConfigParamsDescriptor{Name: "myproxy_server_pwd", Type: "string", Default: ""},
			l.ConfigParamsDescriptor{Name: "script_path", Type: "string", Default: "./ssh_trigger.py"},
			l.ConfigParamsDescriptor{Name: "remote_script", Type: "string", Default: "./myproxy_ssh_vm.py"},
			l.ConfigParamsDescriptor{Name: "host", Type: "string", Default: "watts-x509.data.kit.edu"},
			l.ConfigParamsDescriptor{Name: "user", Type: "string", Default: "x509"},
			l.ConfigParamsDescriptor{Name: "work_dir", Type: "string", Default: "/tmp"},
		},
		RequestParams: []l.RequestParamsDescriptor{
			l.RequestParamsDescriptor{
				Key: "pub_key", Name: "public key", Description: "the public key of the service", Type: "textarea",
				Mandatory: false},
		},
	}
	l.PluginRun(pluginDescriptor)
}
