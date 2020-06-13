package main

import (
	"go.uber.org/zap"
	"gotlsclient/tlslib"
)

func main() {
	logger, _ := zap.NewProduction()
	defer logger.Sync()
	sLogger := logger.Sugar()

	certFile := "/path/to/cert.crt"
	keyFile := "/path/to/key.key"
	cafile := "/path/to/ca.crt"

	tlsFactory := tlslib.New(certFile, keyFile, cafile, sLogger)
	httpClient := tlsFactory.ConfigureHTTPSClient()
	httpClient.Get("https://example.com/")
}
