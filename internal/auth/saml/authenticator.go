package saml

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/sirupsen/logrus"
)

// Config SAML設定
type Config struct {
	EntityID         string `json:"entity_id"`
	IDPURL          string `json:"idp_url"`
	IDPEntityID     string `json:"idp_entity_id"`
	X509Cert        string `json:"x509_cert"`
	SPACSURL        string `json:"sp_acs_url"`
	SPSLDURL        string `json:"sp_sls_url"`
	SPX509Cert      string `json:"sp_x509_cert,omitempty"`
	SPPrivateKey    string `json:"sp_private_key,omitempty"`
}

// Authenticator SAML認証器
type Authenticator struct {
	config       *Config
	samlSP       *samlsp.Middleware
	logger       *logrus.Logger
}

// UserData 認証済みユーザー情報
type UserData struct {
	NameID         string                 `json:"name_id"`
	NameIDFormat   string                 `json:"name_id_format"`
	Attributes     map[string][]string    `json:"attributes"`
	SessionIndex   string                 `json:"session_index"`
}

// NewAuthenticator 新しいSAML認証器を作成
func NewAuthenticator(config *Config) (*Authenticator, error) {
	logger := logrus.New()
	
	// IdP証明書をパース
	idpCertPEM := "-----BEGIN CERTIFICATE-----\n" + config.X509Cert + "\n-----END CERTIFICATE-----"
	idpCertBlock, _ := pem.Decode([]byte(idpCertPEM))
	if idpCertBlock == nil {
		return nil, fmt.Errorf("failed to parse IdP certificate")
	}
	
	idpCert, err := x509.ParseCertificate(idpCertBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse IdP certificate: %w", err)
	}

	// SAML SP設定
	idpURL, err := url.Parse(config.IDPURL)
	if err != nil {
		return nil, fmt.Errorf("invalid IdP URL: %w", err)
	}

	acsURL, err := url.Parse(config.SPACSURL)
	if err != nil {
		return nil, fmt.Errorf("invalid ACS URL: %w", err)
	}

	// SAMLサービスプロバイダー作成
	samlSP, err := samlsp.New(samlsp.Options{
		IDPMetadata: &saml.EntityDescriptor{
			EntityID: config.IDPEntityID,
			IDPSSODescriptors: []saml.IDPSSODescriptor{
				{
					SSODescriptor: saml.SSODescriptor{
						RoleDescriptor: saml.RoleDescriptor{
							ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
							KeyDescriptors: []saml.KeyDescriptor{
								{
									Use: "signing",
									KeyInfo: saml.KeyInfo{
										Certificate: base64.StdEncoding.EncodeToString(idpCert.Raw),
									},
								},
							},
						},
					},
					SingleSignOnServices: []saml.Endpoint{
						{
							Binding:  saml.HTTPRedirectBinding,
							Location: config.IDPURL,
						},
					},
				},
			},
		},
		URL:         *acsURL,
		EntityID:    config.EntityID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create SAML SP: %w", err)
	}

	return &Authenticator{
		config: config,
		samlSP: samlSP,
		logger: logger,
	}, nil
}

// CreateAuthRequest SAML認証リクエストを生成
func (a *Authenticator) CreateAuthRequest(acsURL, relayState string) (string, error) {
	// AuthnRequestを生成
	req, err := a.samlSP.ServiceProvider.MakeAuthenticationRequest(a.samlSP.ServiceProvider.GetSSOBindingLocation(saml.HTTPRedirectBinding), saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	if err != nil {
		a.logger.WithError(err).Error("Failed to create authentication request")
		return "", fmt.Errorf("failed to create authentication request: %w", err)
	}

	// リダイレクトURLを生成
	if relayState != "" {
		req.RelayState = relayState
	}

	redirectURL := req.Redirect("", &a.samlSP.ServiceProvider).String()
	
	a.logger.WithFields(logrus.Fields{
		"entity_id":    a.config.EntityID,
		"acs_url":      acsURL,
		"relay_state":  relayState,
	}).Info("SAML auth request created")

	return redirectURL, nil
}

// ValidateResponse SAMLレスポンスを検証
func (a *Authenticator) ValidateResponse(r *http.Request) (*UserData, error) {
	// SAMLレスポンスを解析
	assertion, err := a.samlSP.ServiceProvider.ParseResponse(r, nil)
	if err != nil {
		a.logger.WithError(err).Error("Failed to parse SAML response")
		return nil, fmt.Errorf("failed to parse SAML response: %w", err)
	}

	// ユーザー情報を抽出
	userData := &UserData{
		NameID:       assertion.Subject.NameID.Value,
		NameIDFormat: assertion.Subject.NameID.Format,
		Attributes:   make(map[string][]string),
	}

	// 属性を抽出
	for _, stmt := range assertion.AttributeStatements {
		for _, attr := range stmt.Attributes {
			var values []string
			for _, value := range attr.AttributeValues {
				values = append(values, value.Value)
			}
			userData.Attributes[attr.Name] = values
		}
	}

	// セッションインデックスを取得
	for _, stmt := range assertion.AuthnStatements {
		userData.SessionIndex = stmt.SessionIndex
		break
	}

	a.logger.WithFields(logrus.Fields{
		"entity_id":        a.config.EntityID,
		"name_id":          userData.NameID,
		"attributes_count": len(userData.Attributes),
	}).Info("SAML response validated successfully")

	return userData, nil
}

// GenerateMetadata SPメタデータXMLを生成
func (a *Authenticator) GenerateMetadata() (string, error) {
	metadata := a.samlSP.ServiceProvider.Metadata()
	
	a.logger.WithFields(logrus.Fields{
		"entity_id": a.config.EntityID,
	}).Info("SP metadata generated successfully")

	return string(metadata), nil
}

// GetServiceProvider SAMLサービスプロバイダーを取得
func (a *Authenticator) GetServiceProvider() *samlsp.Middleware {
	return a.samlSP
} 