package handlers

import "github.com/finnapigo/finnapigo/internal/services"

// HTTP request/response payload structs. Each endpoint that accepts a body has
// a dedicated struct with gin binding tags — never accept raw maps.

type RegisterRequest struct {
	Username string `json:"username" binding:"required,min=3,max=50"`
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
	FullName string `json:"fullName" binding:"required,max=255"`
}

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refreshToken" binding:"required"`
}

type LogoutRequest struct {
	RefreshToken string `json:"refreshToken" binding:"required"`
}

type ForgotPasswordRequest struct {
	Email string `json:"email" binding:"required,email"`
}

type ResetPasswordRequest struct {
	Token       string `json:"token" binding:"required"`
	NewPassword string `json:"newPassword" binding:"required,min=8"`
}

type ChangePasswordRequest struct {
	OldPassword string `json:"oldPassword" binding:"required"`
	NewPassword string `json:"newPassword" binding:"required,min=8"`
}

type VerifyEmailRequest struct {
	Token string `json:"token" binding:"required"`
}

type OTPSendRequest struct {
	Purpose string `json:"purpose" binding:"required"`
}

type OTPVerifyRequest struct {
	Code    string `json:"code" binding:"required,len=6"`
	Purpose string `json:"purpose" binding:"required"`
}

// ---- response payloads ----

type RegisterResponse struct {
	Profile          services.UserProfile `json:"profile"`
	VerifyEmailToken string               `json:"verifyEmailToken,omitempty"`
}

type LoginResponse struct {
	Profile services.UserProfile `json:"profile"`
	services.TokenPair
}

type MessageOnly struct {
	Message string `json:"message,omitempty"`
}
