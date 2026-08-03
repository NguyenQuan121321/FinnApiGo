// Package utils contains cross-cutting helpers: the standardized JSON
// response formatter, hashing primitives, and JWT helpers.
package utils

import "github.com/gin-gonic/gin"

// APIResponse is the single canonical envelope for every endpoint.
// All handlers return this shape via Respond, success or error.
type APIResponse struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data"`
}

// Respond is the ONE shared response helper. Handlers must never call
// c.JSON directly — always go through here so the envelope stays consistent.
func Respond(c *gin.Context, code int, message string, data interface{}) {
	c.JSON(code, APIResponse{
		Code:    code,
		Message: message,
		Data:    data,
	})
}
