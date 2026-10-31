package agentclient

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"
)

// TLSOptions règle la vérification du serveur et le certificat client.
type TLSOptions struct {
	// CAFile est un fichier PEM d'autorités de certification ; s'il est donné, seules
	// elles sont reconnues (autorité privée), sinon celles du système.
	CAFile string
	// ClientCertFile et ClientKeyFile sont le certificat client (PEM) et sa clé, pour le
	// mTLS ; tous deux ou aucun. Ils sont relus quand ils changent sur le disque, si bien
	// qu'un certificat renouvelé sert sans redémarrer l'agent.
	ClientCertFile string
	ClientKeyFile  string
}

// newTransport construit le transport HTTPS : TLS 1.2 au moins, autorités, certificat
// client et mandataire.
func newTransport(o TLSOptions, proxy string) (*http.Transport, error) {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	t.ResponseHeaderTimeout = 0 // borné par Options.Timeout
	t.Proxy = http.ProxyFromEnvironment
	if proxy != "" {
		u, err := url.Parse(proxy)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return nil, fmt.Errorf("agentclient: mandataire invalide (http://hôte:port attendu)")
		}
		t.Proxy = http.ProxyURL(u)
	}
	if o.CAFile != "" {
		pem, err := os.ReadFile(o.CAFile)
		if err != nil {
			return nil, fmt.Errorf("agentclient: autorité de certification : %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("agentclient: autorité de certification %s : aucun certificat PEM", o.CAFile)
		}
		t.TLSClientConfig.RootCAs = pool
	}
	switch {
	case o.ClientCertFile != "" && o.ClientKeyFile != "":
		kp := &keyPair{cert: o.ClientCertFile, key: o.ClientKeyFile}
		if _, err := kp.get(); err != nil {
			return nil, err
		}
		// Le certificat est présenté même si le serveur annonce d'autres autorités : c'est
		// au serveur de le refuser, avec une erreur explicite.
		t.TLSClientConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return kp.get()
		}
	case o.ClientCertFile != "" || o.ClientKeyFile != "":
		return nil, errors.New("agentclient: certificat client et clé vont ensemble")
	}
	return t, nil
}

// keyPair garde le certificat client chargé et le relit quand l'un de ses fichiers change.
type keyPair struct {
	cert, key string

	mu      sync.Mutex
	loaded  *tls.Certificate
	modTime [2]time.Time
}

func (k *keyPair) get() (*tls.Certificate, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	var mt [2]time.Time
	for i, p := range []string{k.cert, k.key} {
		fi, err := os.Stat(p)
		if err != nil {
			return nil, fmt.Errorf("agentclient: certificat client : %w", err)
		}
		mt[i] = fi.ModTime()
	}
	if k.loaded != nil && mt == k.modTime {
		return k.loaded, nil
	}
	c, err := tls.LoadX509KeyPair(k.cert, k.key)
	if err != nil {
		return nil, fmt.Errorf("agentclient: certificat client : %w", err)
	}
	k.loaded, k.modTime = &c, mt
	return k.loaded, nil
}
