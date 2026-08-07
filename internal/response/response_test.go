package response

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestRespondEnvelope(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tc := range []struct {
		name    string
		code    int
		message string
		data    any
	}{
		{"success with data", 200, "ok", gin.H{"id": 1}},
		{"success nil", 200, "empty", nil},
		{"error", 400, "invalid", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(r)
			Respond(c, tc.code, tc.message, tc.data)
			var body map[string]json.RawMessage
			if err := json.Unmarshal(r.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if len(body) != 3 || body["code"] == nil || body["message"] == nil || body["data"] == nil {
				t.Fatalf("unexpected envelope: %s", r.Body.String())
			}
		})
	}
}
