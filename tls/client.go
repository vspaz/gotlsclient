package tls

import (
	"crypto/tls"
	"crypto/x509"
	"go.uber.org/zap"
	"io/ioutil"
	"net/http"
	"os"
)

type TLSClient struct {
	certFile string
	keyFile  string
	caFile   string
	logger   *zap.SugaredLogger
}

func New(certFile string, keyFile string, caFile string, logger *zap.SugaredLogger) *TLSClient {
	return &TLSClient{
		certFile,
		keyFile,
		caFile,
		logger,
	}
}

func (tlsclient *TLSClient) loadCertPair() *tls.Certificate {
	certs, err := tls.LoadX509KeyPair(tlsclient.certFile, tlsclient.keyFile)
	if err != nil {
		tlsclient.logger.Error("failed to load certificates from disk")
		os.Exit(-1)
	}
	return &certs
}

func (tlsclient *TLSClient) loadCA() []byte {
	caCert, err := ioutil.ReadFile(tlsclient.caFile)
	if err != nil {
		tlsclient.logger.Error("failed to load ca certificate from disk")
		os.Exit(-1)
	}
	return caCert
}

func (tlsclient *TLSClient) createCertPool(ca []byte) *x509.CertPool {
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(ca)

	return caCertPool
}

func (tlsclient *TLSClient) setupHTTPS(certs tls.Certificate, caPool *x509.CertPool) *http.Client {
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{certs},
		RootCAs:      caPool,
	}
	tlsConfig.BuildNameToCertificate()
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Transport: transport}
	return client
}

func (tlsclient *TLSClient) ConfigureHTTPSClient() *http.Client {
	certPair := tlsclient.loadCertPair()
	ca := tlsclient.loadCA()
	certPool := tlsclient.createCertPool(ca)
	httpClient := tlsclient.setupHTTPS(*certPair, certPool)
	return httpClient
}
