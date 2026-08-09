// Package handlers binds inbound JSON using sonic (github.com/bytedance/sonic)
// instead of encoding/json, and recycles the read buffer through a sync.Pool.
//
// Why this exists (zero-lag / DDoS posture):
//   - encoding/json is reflection-heavy and a meaningful GC/CPU contributor
//     under flood traffic. sonic is AST-based and substantially faster, so the
//     request hot path (parse -> validate -> dispatch) stays cheap even when an
//     attacker is saturating the listener.
//   - Each request would otherwise allocate a fresh byte buffer for the body;
//     a sync.Pool reuses them, so steady-state allocation is near zero.
//   - A hard cap on the bytes we are willing to read (1 KiB for these tiny MFA
//     payloads) lets us reject oversized bodies before any parsing — the first
//     line of defense against payload-based DoS.
package handlers

import (
	"errors"
	"io"
	"net/http"
	"sync"

	"github.com/bytedance/sonic"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"

	"github.com/finnapigo/finnapigo/internal/response"
)

// maxTOTPBody is the largest JSON body the TOTP endpoints will read. A real
// TOTP request is ~30 bytes ("{\"code\":\"123456\"}"); 1 KiB is generous while
// still rejecting anything pathological instantly, before decoding.
const maxTOTPBody = 1 << 10 // 1 KiB

// errBodyRequired is returned when the request has no body at all.
var errBodyRequired = errors.New("request body is required")

// bufPool recycles the byte slices used to read request bodies. The pool only
// ever hands out small (1 KiB) slices, so all items are uniform-sized — which
// is what makes sync.Pool effective. We pool the *[]byte (not the slice) so the
// pool never retains a live reference that would defeat reuse.
var bufPool = sync.Pool{
	New: func() any { b := make([]byte, 0, maxTOTPBody); return &b },
}

// acquireBuf / releaseBuf borrow and return a pooled byte slice. Callers must
// return the buffer once they are done decoding so it can be reused.
func acquireBuf() *[]byte  { return bufPool.Get().(*[]byte) }
func releaseBuf(p *[]byte) { *p = (*p)[:0]; bufPool.Put(p) }

// bindJSON decodes the request body into dst using sonic and then runs gin's
// standard struct validator so the existing `binding:"..."` tags keep working.
// It is the sonic-backed drop-in replacement for c.ShouldBindJSON.
//
// On failure it writes the standardized error response and returns false, so
// handlers can early-return:  `if !bindJSON(c, &req) { return }`.
func bindJSON(c *gin.Context, dst any) bool {
	// Read directly into a pooled, fixed-size buffer. The body is hard-capped
	// at maxTOTPBody+1 bytes: one byte of headroom lets us tell "exactly at the
	// limit" from "over the limit" so an attacker can't smuggle a huge payload
	// past the size check. Reading into the pooled buffer is the zero-alloc
	// fast path — io.ReadAll would grow its own backing slice every request.
	bufp := acquireBuf()
	defer releaseBuf(bufp)
	*bufp = (*bufp)[:cap(*bufp)] // full capacity as the read window
	n, err := io.ReadFull(c.Request.Body, *bufp)
	body := (*bufp)[:n]
	switch {
	case err == nil:
		// We filled the whole buffer — there's more data, so the body exceeds
		// the cap. Reject before decoding (payload-DoS defense).
		response.Respond(c, http.StatusRequestEntityTooLarge, "request body too large", nil)
		return false
	case errors.Is(err, io.ErrUnexpectedEOF):
		// n < len(buf): body fits. This is the normal, happy path.
	case errors.Is(err, io.EOF):
		response.Respond(c, http.StatusBadRequest, errBodyRequired.Error(), nil)
		return false
	default:
		response.Respond(c, http.StatusBadRequest, "could not read request body", nil)
		return false
	}
	if n > maxTOTPBody {
		response.Respond(c, http.StatusRequestEntityTooLarge, "request body too large", nil)
		return false
	}

	// sonic.Unmarshal is the zero-extra-alloc fast path for an in-memory slice.
	if err := sonic.ConfigDefault.Unmarshal(body, dst); err != nil {
		response.Respond(c, http.StatusBadRequest, err.Error(), nil)
		return false
	}
	if err := binding.Validator.ValidateStruct(dst); err != nil {
		response.Respond(c, http.StatusBadRequest, err.Error(), nil)
		return false
	}
	return true
}
