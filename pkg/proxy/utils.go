package proxy

import (
	"bytes"
	"fmt"
	"io"
	"net/http"

	"github.com/openkruise/agents/pkg/sandbox-manager/consts"
)

var requestPeerClient = &http.Client{
	Timeout: consts.RequestPeerTimeout,
}

func requestPeer(method, ip, path string, body []byte) error {
	var buf io.Reader
	if len(body) > 0 {
		buf = bytes.NewReader(body)
	}
	request, err := http.NewRequest(method, fmt.Sprintf("http://%s:%d%s", ip, SystemPort, path), buf)
	if err != nil {
		return err
	}

	resp, err := requestPeerClient.Do(request)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("request to peer %s failed with status code: %d", ip, resp.StatusCode)
	}

	return nil
}
