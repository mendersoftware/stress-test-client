// Copyright 2021 Northern.tech AS
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.

package client

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/mendersoftware/stress-test-client/model"
)

const urlAuthRequest = "/api/devices/v1/authentication/auth_requests"
const urlPutInventory = "/api/devices/v1/inventory/device/attributes"
const urlDeploymentsNext = "/api/devices/v1/deployments/device/deployments/next"
const urlDeploymentsStatus = "/api/devices/v1/deployments/device/deployments/{id}/status"

const (
	statusDownloading = "downloading"
	statusInstalling  = "installing"
	statusRebooting   = "rebooting"
	statusSuccess     = "success"
)

const attributeArtifactName = "artifact_name"

type Client struct {
	Index        int64
	MACAddress   string
	JWTToken     string
	Config       *model.RunConfig
	ArtifactName string
}

type AuthRequest struct {
	IdentityData string `json:"id_data"`
	PublicKey    string `json:"pubkey"`
	TenantToken  string `json:"tenant_token"`
}

type IdentityData struct {
	MAC string `json:"mac"`
}

func getMACAddressFromPrefixAndIndex(prefix string, index int64) (string, error) {
	prefixNum, err := strconv.ParseUint(prefix, 16, 8)
	if err != nil {
		return "", err
	}
	buf := make([]byte, 6)
	buf[0] = byte(prefixNum)
	buf[1] = byte(int64(index>>32) & 255)
	buf[2] = byte(int64(index>>24) & 255)
	buf[3] = byte(int64(index>>16) & 255)
	buf[4] = byte(int64(index>>8) & 255)
	buf[5] = byte(int64(index) & 255)

	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]), nil
}

func NewClient(config *model.RunConfig, index int64) (*Client, error) {
	macAddress, err := getMACAddressFromPrefixAndIndex(config.MACAddressPrefix, index)
	if err != nil {
		return nil, err
	}

	return &Client{
		Index:        index,
		MACAddress:   macAddress,
		Config:       config,
		ArtifactName: config.ArtifactName,
	}, nil
}

func (c *Client) Authenticate() error {
	identityData := &IdentityData{MAC: c.MACAddress}
	identityDataBytes, err := json.Marshal(identityData)
	if err != nil {
		return err
	}

	authRequest := &AuthRequest{
		IdentityData: string(identityDataBytes),
		PublicKey:    string(c.Config.PublicKey),
		TenantToken:  c.Config.TenantToken,
	}

	body, err := json.Marshal(authRequest)
	if err != nil {
		return err
	}

	hashed := sha256.Sum256(body)
	bodyHash, err := rsa.SignPKCS1v15(rand.Reader, c.Config.PrivateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return err
	}
	signature := base64.StdEncoding.EncodeToString(bodyHash)

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	for {
		req, err := http.NewRequest(http.MethodPost, c.Config.ServerURL+urlAuthRequest, bytes.NewBuffer(body))
		if err != nil {
			return err
		}
		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("X-MEN-Signature", signature)

		start := time.Now()
		response, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		elapsed := time.Since(start).Milliseconds()

		log.Debugf("[%s] %-40s %d (%6d ms)", c.MACAddress, "authentication", response.StatusCode, elapsed)

		if response.StatusCode == http.StatusOK {
			body, err := ioutil.ReadAll(response.Body)
			if err != nil {
				return err
			}
			c.JWTToken = string(body)
			return nil
		}

		time.Sleep(c.Config.AuthInterval)
	}
}

func (c *Client) Run() {
	err := c.Authenticate()
	if err != nil {
		log.Errorf("[%s] %s", c.MACAddress, err)
		return
	}

	inventoryTicker := time.NewTicker(c.Config.InventoryInterval)
	updateTicker := time.NewTicker(c.Config.UpdateInterval)

	c.SendInventory()
	c.UpdateCheck()

	for {
		select {
		case <-inventoryTicker.C:
			c.SendInventory()
		case <-updateTicker.C:
			c.UpdateCheck()
		}
	}
}

func (c *Client) SendInventory() {
	attributes := []*model.InventoryAttribute{
		{
			Name:  attributeArtifactName,
			Value: c.ArtifactName,
		},
	}
	for _, attr := range c.Config.InventoryAttributes {
		parts := strings.SplitN(attr, ":", 2)
		if len(parts) < 2 {
			continue
		}
		name := parts[0]
		values := strings.Split(parts[1], "|")
		value := values[int(c.Index)%len(values)]
		attributes = append(attributes, &model.InventoryAttribute{
			Name:  name,
			Value: value,
		})
	}

	body, err := json.Marshal(attributes)
	if err != nil {
		log.Errorf("[%s] %s", c.MACAddress, err)
		return
	}

	req, err := http.NewRequest(http.MethodPut, c.Config.ServerURL+urlPutInventory, bytes.NewBuffer(body))
	if err != nil {
		log.Errorf("[%s] %s", c.MACAddress, err)
		return
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Bearer "+c.JWTToken)

	start := time.Now()
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Errorf("[%s] %s", c.MACAddress, err)
		return
	}
	elapsed := time.Since(start).Milliseconds()

	log.Debugf("[%s] %-40s %d (%6d ms)", c.MACAddress, "send-inventory", response.StatusCode, elapsed)
}

func (c *Client) UpdateCheck() {
	deploymentNextRequest := &model.DeploymentNextRequest{
		DeviceType:          c.Config.DeviceType,
		ArtifactName:        c.Config.ArtifactName,
		RootfsImageChecksum: c.Config.RootfsImageChecksum,
	}
	body, err := json.Marshal(deploymentNextRequest)
	if err != nil {
		log.Errorf("[%s] %s", c.MACAddress, err)
		return
	}

	req, err := http.NewRequest(http.MethodPost, c.Config.ServerURL+urlDeploymentsNext, bytes.NewBuffer(body))
	if err != nil {
		log.Errorf("[%s] %s", c.MACAddress, err)
		return
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Bearer "+c.JWTToken)

	start := time.Now()
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Errorf("[%s] %s", c.MACAddress, err)
		return
	}
	elapsed := time.Since(start).Milliseconds()

	log.Debugf("[%s] %-40s %d (%6d ms)", c.MACAddress, "send-inventory", response.StatusCode, elapsed)

	// received deployment
	if response.StatusCode == http.StatusOK {
		body, err := ioutil.ReadAll(response.Body)
		if err != nil {
			log.Errorf("[%s] %s", c.MACAddress, err)
			return
		}

		response := &model.DeploymentNextResponse{}
		err = json.Unmarshal(body, response)
		if err != nil {
			log.Errorf("[%s] %s", c.MACAddress, err)
			return
		}

		c.Deployment(response.ID, response.Artifact)

		// report the new artifact name
		c.ArtifactName = response.Artifact.Name
		c.SendInventory()
	}
}

func (c *Client) Deployment(deploymentID string, artifact *model.DeploymentNextArtifact) {
	statusURL := strings.Replace(urlDeploymentsStatus, "{id}", deploymentID, 1)

	statuses := []string{
		statusDownloading,
		statusInstalling,
		statusRebooting,
		statusSuccess,
	}

	for _, status := range statuses {
		deploymentNextRequest := &model.DeploymentStatus{
			Status: status,
		}

		body, err := json.Marshal(deploymentNextRequest)
		if err != nil {
			log.Errorf("[%s] %s", c.MACAddress, err)
			return
		}

		req, err := http.NewRequest(http.MethodPut, c.Config.ServerURL+statusURL, bytes.NewBuffer(body))
		if err != nil {
			log.Errorf("[%s] %s", c.MACAddress, err)
			return
		}
		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("Authorization", "Bearer "+c.JWTToken)

		start := time.Now()
		response, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Errorf("[%s] %s", c.MACAddress, err)
			return
		}
		elapsed := time.Since(start).Milliseconds()

		log.Debugf("[%s] %-40s %d (%6d ms)", c.MACAddress, "deployment-status: "+status, response.StatusCode, elapsed)

		time.Sleep(c.Config.DeploymentTime)
	}
}
