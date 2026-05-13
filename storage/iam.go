package storage

import (
	"github.com/hanzoai/oss"
	iamStorage "github.com/hanzoai/oss/iam"
)

func NewIamStorageProvider(providerType string, clientId string, clientSecret string, region string, bucket string, endpoint string, cert string, content string) oss.StorageInterface {
	sp := iamStorage.New(&iamStorage.Config{
		AccessID:         clientId,
		AccessKey:        clientSecret,
		Endpoint:         endpoint,
		Certificate:      cert,
		ApplicationName:  region,
		OrganizationName: content,
		Provider:         bucket,
	})
	return sp
}
