package services

import (
	"context"
	"errors"
	"github.com/finnapigo/finnapigo/internal/audit"
	"github.com/finnapigo/finnapigo/internal/database"
	"github.com/finnapigo/finnapigo/internal/models"
	"net/http"
	"time"
)

type auditOperationRepo interface {
	AuditOperation(context.Context, func(context.Context) error, func(error) bool) error
}

// Every security service entry below uses the production audit transaction.
// Returning zero values on failure prevents token material escaping a rollback.
func runAuditOperation(ctx context.Context, repo any, fn func(context.Context) error) error {
	if r, ok := repo.(auditOperationRepo); ok {
		return r.AuditOperation(ctx, fn, auditDenial)
	}
	return fn(ctx)
}
func auditDenial(err error) bool {
	for _, denial := range []error{ErrInvalidCredentials, ErrInvalidToken, ErrInvalidCode, ErrAccountLocked, ErrAccountDisabled, ErrRateLimited, ErrPasskeyCredentialRevoked} {
		if errors.Is(err, denial) {
			return true
		}
	}
	return false
}
func (s *AuthService) Register(ctx context.Context, in RegisterInput) (UserProfile, error) {
	var r0 UserProfile
	err := runAuditOperation(ctx, s.audits, func(inner context.Context) error {
		var innerErr error
		r0, innerErr = s.registerAudited(inner, in)
		return innerErr
	})
	if err != nil {
		return UserProfile{}, err
	}
	return r0, nil
}

func (s *AuthService) Login(ctx context.Context, in LoginInput, ip, ua string) (TokenPair, UserProfile, *MFAPendingResult, error) {
	var r0 TokenPair
	var r1 UserProfile
	var r2 *MFAPendingResult
	err := runAuditOperation(ctx, s.audits, func(inner context.Context) error {
		var innerErr error
		r0, r1, r2, innerErr = s.loginAudited(inner, in, ip, ua)
		return innerErr
	})
	if err != nil {
		return TokenPair{}, UserProfile{}, nil, err
	}
	return r0, r1, r2, nil
}

func (s *AuthService) CompleteMFALogin(ctx context.Context, in CompleteMFALoginInput) (TokenPair, UserProfile, error) {
	var r0 TokenPair
	var r1 UserProfile
	err := runAuditOperation(ctx, s.audits, func(inner context.Context) error {
		var innerErr error
		r0, r1, innerErr = s.completeMFALoginAudited(inner, in)
		return innerErr
	})
	if err != nil {
		return TokenPair{}, UserProfile{}, err
	}
	return r0, r1, nil
}

func (s *AuthService) CheckMFAOrIssueTokens(ctx context.Context, user *models.User, ip, ua, auditDetail string) (TokenPair, UserProfile, *MFAPendingResult, error) {
	var r0 TokenPair
	var r1 UserProfile
	var r2 *MFAPendingResult
	err := runAuditOperation(ctx, s.audits, func(inner context.Context) error {
		var innerErr error
		r0, r1, r2, innerErr = s.checkMFAOrIssueTokensAudited(inner, user, ip, ua, auditDetail)
		return innerErr
	})
	if err != nil {
		return TokenPair{}, UserProfile{}, nil, err
	}
	return r0, r1, r2, nil
}

func (s *AuthService) Logout(ctx context.Context, refreshToken, accessJTI, ip string) error {

	err := runAuditOperation(ctx, s.audits, func(inner context.Context) error {
		return s.logoutAudited(inner, refreshToken, accessJTI, ip)
	})
	if err != nil {
		return err
	}
	return nil
}

func (s *AuthService) LogoutAll(ctx context.Context, userID uint, ip string) error {

	err := runAuditOperation(ctx, s.audits, func(inner context.Context) error {
		return s.logoutAllAudited(inner, userID, ip)
	})
	if err != nil {
		return err
	}
	return nil
}

func (s *AuthService) Refresh(ctx context.Context, refreshToken, ip, ua string) (TokenPair, error) {
	var r0 TokenPair
	err := runAuditOperation(ctx, s.audits, func(inner context.Context) error {
		var innerErr error
		r0, innerErr = s.refreshAudited(inner, refreshToken, ip, ua)
		return innerErr
	})
	if err != nil {
		return TokenPair{}, err
	}
	return r0, nil
}

func (s *AuthService) ResendVerifyEmail(ctx context.Context, email, ip string) error {
	return s.resendVerifyEmailAudited(ctx, email, ip)
}

func (s *AuthService) ResetPassword(ctx context.Context, in ResetPasswordInput, ip string) error {

	err := runAuditOperation(ctx, s.audits, func(inner context.Context) error {
		return s.resetPasswordAudited(inner, in, ip)
	})
	if err != nil {
		return err
	}
	return nil
}

func (s *AuthService) ChangePassword(ctx context.Context, in ChangePasswordInput, ip string) error {

	err := runAuditOperation(ctx, s.audits, func(inner context.Context) error {
		return s.changePasswordAudited(inner, in, ip)
	})
	if err != nil {
		return err
	}
	return nil
}

func (s *AuthService) SetPassword(ctx context.Context, userID uint, newPassword, ip string) error {

	err := runAuditOperation(ctx, s.audits, func(inner context.Context) error {
		return s.setPasswordAudited(inner, userID, newPassword, ip)
	})
	if err != nil {
		return err
	}
	return nil
}

func (s *AuthService) RequestChangeEmail(ctx context.Context, userID uint, in ChangeEmailRequestInput, ip string) error {
	return s.requestChangeEmailAudited(ctx, userID, in, ip)
}

func (s *AuthService) ConfirmChangeEmail(ctx context.Context, token, ip string) error {

	err := runAuditOperation(ctx, s.audits, func(inner context.Context) error {
		return s.confirmChangeEmailAudited(inner, token, ip)
	})
	if err != nil {
		return err
	}
	return nil
}

func (s *AuthService) DeactivateAccount(ctx context.Context, userID uint, sudoToken, password, accessJTI, ip string) error {

	err := runAuditOperation(ctx, s.audits, func(inner context.Context) error {
		return s.deactivateAccountAudited(inner, userID, sudoToken, password, accessJTI, ip)
	})
	if err != nil {
		return err
	}
	return nil
}

func (s *AuthService) EraseAccount(ctx context.Context, userID uint, sudoToken, password, accessJTI, ip string) error {

	err := runAuditOperation(ctx, s.audits, func(inner context.Context) error {
		return s.eraseAccountAudited(inner, userID, sudoToken, password, accessJTI, ip)
	})
	if err != nil {
		return err
	}
	return nil
}

func (s *AuthService) VerifyEmail(ctx context.Context, in EmailVerifyInput) error {

	err := runAuditOperation(ctx, s.audits, func(inner context.Context) error {
		return s.verifyEmailAudited(inner, in)
	})
	if err != nil {
		return err
	}
	return nil
}

func (s *AuthService) RevokeSession(ctx context.Context, sessionID string, userID uint, ip string) error {

	err := runAuditOperation(ctx, s.audits, func(inner context.Context) error {
		return s.revokeSessionAudited(inner, sessionID, userID, ip)
	})
	if err != nil {
		return err
	}
	return nil
}

func (s *AuthService) IssuePasskeyTokenPair(ctx context.Context, user *models.User, ip, ua string) (TokenPair, UserProfile, error) {
	var r0 TokenPair
	var r1 UserProfile
	err := runAuditOperation(ctx, s.audits, func(inner context.Context) error {
		var innerErr error
		r0, r1, innerErr = s.issuePasskeyTokenPairAudited(inner, user, ip, ua)
		return innerErr
	})
	if err != nil {
		return TokenPair{}, UserProfile{}, err
	}
	return r0, r1, nil
}

func (s *AdminService) LockUser(ctx context.Context, adminID, targetUserID uint, lockDuration time.Duration, ip string) error {
	ctx = audit.WithActor(ctx, adminID)

	err := runAuditOperation(ctx, s.audits, func(inner context.Context) error {
		return s.lockUserAudited(inner, adminID, targetUserID, lockDuration, ip)
	})
	if err != nil {
		return err
	}
	return nil
}

func (s *AdminService) UnlockUser(ctx context.Context, adminID, targetUserID uint, ip string) error {
	ctx = audit.WithActor(ctx, adminID)

	err := runAuditOperation(ctx, s.audits, func(inner context.Context) error {
		return s.unlockUserAudited(inner, adminID, targetUserID, ip)
	})
	if err != nil {
		return err
	}
	return nil
}

func (s *AdminService) ForceLogout(ctx context.Context, adminID, targetUserID uint, ip string) error {
	ctx = audit.WithActor(ctx, adminID)

	err := runAuditOperation(ctx, s.audits, func(inner context.Context) error {
		return s.forceLogoutAudited(inner, adminID, targetUserID, ip)
	})
	if err != nil {
		return err
	}
	return nil
}

func (s *TOTPService) Enable(ctx context.Context, userID uint, email, sudoToken string) (string, string, error) {
	var r0 string
	var r1 string
	err := runAuditOperation(ctx, s.audits, func(inner context.Context) error {
		var innerErr error
		r0, r1, innerErr = s.enableAudited(inner, userID, email, sudoToken)
		return innerErr
	})
	if err != nil {
		return "", "", err
	}
	return r0, r1, nil
}

func (s *TOTPService) VerifyEnable(ctx context.Context, userID uint, code string) ([]string, error) {
	var r0 []string
	err := runAuditOperation(ctx, s.audits, func(inner context.Context) error {
		var innerErr error
		r0, innerErr = s.verifyEnableAudited(inner, userID, code)
		return innerErr
	})
	if err != nil {
		return nil, err
	}
	return r0, nil
}

func (s *TOTPService) Validate(ctx context.Context, userID uint, code string) error {

	err := runAuditOperation(ctx, s.audits, func(inner context.Context) error {
		return s.validateAudited(inner, userID, code)
	})
	if err != nil {
		return err
	}
	return nil
}

func (s *TOTPService) ViewRecoveryCodes(ctx context.Context, userID uint, code string) ([]string, error) {
	var r0 []string
	err := runAuditOperation(ctx, s.audits, func(inner context.Context) error {
		var innerErr error
		r0, innerErr = s.viewRecoveryCodesAudited(inner, userID, code)
		return innerErr
	})
	if err != nil {
		return nil, err
	}
	return r0, nil
}

func (s *TOTPService) RegenerateRecoveryCodes(ctx context.Context, userID uint) ([]string, error) {
	var r0 []string
	err := runAuditOperation(ctx, s.audits, func(inner context.Context) error {
		var innerErr error
		r0, innerErr = s.regenerateRecoveryCodesAudited(inner, userID)
		return innerErr
	})
	if err != nil {
		return nil, err
	}
	return r0, nil
}

func (s *TOTPService) Disable(ctx context.Context, userID uint, sudoToken, password, code, ip string) error {

	err := runAuditOperation(ctx, s.audits, func(inner context.Context) error {
		return s.disableAudited(inner, userID, sudoToken, password, code, ip)
	})
	if err != nil {
		return err
	}
	return nil
}

func (s *OAuthService) HandleCallback(ctx context.Context, code, state, ip, ua string) (TokenPair, UserProfile, *MFAPendingResult, error) {
	var r0 TokenPair
	var r1 UserProfile
	var r2 *MFAPendingResult
	err := runAuditOperation(ctx, s.audits, func(inner context.Context) error {
		var innerErr error
		r0, r1, r2, innerErr = s.handleCallbackAudited(inner, code, state, ip, ua)
		return innerErr
	})
	if err != nil {
		return TokenPair{}, UserProfile{}, nil, err
	}
	return r0, r1, r2, nil
}

func (s *OAuthService) Unlink(ctx context.Context, userID uint, provider, ip string) error {

	err := runAuditOperation(ctx, s.audits, func(inner context.Context) error {
		return s.unlinkAudited(inner, userID, provider, ip)
	})
	if err != nil {
		return err
	}
	return nil
}

func (s *passkeyService) FinishRegistration(ctx context.Context, userID uint, r *http.Request) (*models.PasskeyCredential, error) {
	var r0 *models.PasskeyCredential
	err := runAuditOperation(ctx, s.audits, func(inner context.Context) error {
		var innerErr error
		r0, innerErr = s.finishRegistrationAudited(inner, userID, r)
		return innerErr
	})
	if err != nil {
		return nil, err
	}
	return r0, nil
}

func (s *passkeyService) FinishAuthentication(ctx context.Context, userID uint, r *http.Request) (*PasskeyAuthResult, error) {
	var r0 *PasskeyAuthResult
	err := runAuditOperation(ctx, s.audits, func(inner context.Context) error {
		var innerErr error
		r0, innerErr = s.finishAuthenticationAudited(inner, userID, r)
		return innerErr
	})
	if err != nil {
		return nil, err
	}
	return r0, nil
}

func (s *passkeyService) Revoke(ctx context.Context, id, userID uint) error {

	err := runAuditOperation(ctx, s.audits, func(inner context.Context) error {
		return s.revokeAudited(inner, id, userID)
	})
	if err != nil {
		return err
	}
	return nil
}

// admitBeforeExternal commits critical evidence before emitting a credential
// over SMTP/Redis/network. It deliberately cannot hide inside an uncommitted
// SQL operation; nontransactional effects follow durable admission.
func admitBeforeExternal(ctx context.Context, repo AuditRepo, e *models.AuditLog) error {
	if repo == nil {
		return nil
	}
	if database.CurrentOperation(ctx) != nil {
		return audit.ErrUnavailable
	}
	return runAuditOperation(ctx, repo, func(inner context.Context) error { repo.Record(inner, e); return nil })
}
