package utils

import (
	"net/http"
	"time"

	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/tb0hdan/certstream-server/pkg/configs"
	"github.com/tb0hdan/certstream-server/pkg/log"
	"go.uber.org/zap"
)

func GetRetryableClient(config *configs.Config, logger *zap.Logger) *http.Client {
	// Create CT client
	retryClient := retryablehttp.NewClient()
	// Set retryablehttp client options
	pooledTransport := cleanhttp.DefaultPooledTransport()
	pooledTransport.MaxIdleConnsPerHost = 10
	pooledTransport.MaxIdleConns = 100
	//
	retryClient.HTTPClient = &http.Client{
		Transport: pooledTransport,
	}
	retryClient.RetryMax = 3
	retryClient.Logger = log.NewLogger(logger)

	// Get the standard client from retryablehttp
	standardClient := retryClient.StandardClient()
	standardClient.Timeout = time.Duration(config.CTLogs.RequestTimeout) * time.Second

	return standardClient
}
