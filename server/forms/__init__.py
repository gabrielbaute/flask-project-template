from .profile_forms import UploadPhotoForm

from .settings_forms import(
    ChangePasswordForm,
    ChangeEmailForm,
    Enable2FAForm,
    Disable2FAForm)

from .auth_forms import(
    LoginForm,
    RegisterForm,
    ResendConfirmationForm,
    ForgotPasswordForm,
    ResetPasswordForm,
    TOTPForm,
    ReactivateAccountForm)