// AuthController.cs
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using VexTrainer.Data.Models;
using VexTrainer.Data.Services;
using VexTrainerAPI.Services;

namespace VexTrainerAPI.Controllers;

/// <summary>
/// Handles all authentication, account management, and identity lifecycle
/// endpoints. This controller is the only place that touches the email and
/// token confirmation flows; every other controller assumes the user is
/// already authenticated via a JWT.
///
/// Dependencies:
///   AuthService              — database layer for all auth operations
///   EmailService             — sends transactional emails (confirmation, reset, deletion)
///   ConfirmationTokenService — generates and validates AES-encrypted, time-limited tokens
///
/// Validation note: input validation in this controller is intentionally minimal.
/// See the "Why controllers don't validate" section at the bottom of this file.
///
/// Endpoint summary:
///   POST /Auth/register                — create account + send confirmation email
///   POST /Auth/confirm-email           — activate account via token link
///   POST /Auth/login                   — authenticate and receive JWT
///   POST /Auth/refresh                 — exchange refresh token for new JWT
///   POST /Auth/logout          [Auth]  — invalidate current session
///   PUT  /Auth/profile         [Auth]  — update email and phone
///   POST /Auth/change-password [Auth]  — change password (requires old password)
///   POST /Auth/forgot-password         — send password reset email
///   POST /Auth/reset-password          — validate reset token and set new password
///   POST /Auth/delete-account/request  — send account deletion confirmation email
///   POST /Auth/delete-account/confirm  — anonymise account via deletion token
/// </summary>
[ApiController]
[Route("[controller]")]
public class AuthController : ControllerBase {
  private readonly AuthService _authService;
  private readonly EmailService _emailService;
  private readonly ConfirmationTokenService _tokenService;
  private readonly ILogger<AuthController> _logger;

  public AuthController(
      AuthService authService,
      EmailService emailService,
      ConfirmationTokenService tokenService,
      ILogger<AuthController> logger) {
    _authService = authService;
    _emailService = emailService;
    _tokenService = tokenService;
    _logger = logger;
  }

  // Register

  /// <summary>
  /// Creates a new user account and sends an email confirmation link.
  ///
  /// The account is created in an inactive state by AuthService/sp_RegisterUser.
  /// The user cannot log in until they click the confirmation link and
  /// POST /Auth/confirm-email. Registration itself always returns 200 so an
  /// attacker cannot detect whether the email address is already taken — but
  /// on a duplicate email the DB returns a non-zero result_code and 400 is
  /// returned (sp_RegisterUser enforces the unique constraint).
  ///
  /// Confirmation email failure is logged but swallowed — the account is
  /// created regardless, and the user can request a re-send in a future
  /// enhancement. This prevents a flaky SMTP server from blocking signups.
  ///
  /// POST /Auth/register
  /// </summary>
  [HttpPost("register")]
  public async Task<IActionResult> Register([FromBody] RegisterRequest request) {
    var result = await _authService.RegisterAsync(request, GetDeviceInfo());

    if (!result.Success)
      return BadRequest(result);

    try {
      var token = _tokenService.GenerateEmailConfirmationToken(request.Email);
      await _emailService.SendEmailConfirmationAsync(request.Email, request.UserName, token);
    }
    catch (Exception ex) {
      _logger.LogWarning(ex, "Confirmation email failed for {Email}", request.Email);
    }

    return Ok(result);
  }

  // Confirm email

  /// <summary>
  /// Activates a user account using the token from the confirmation email link.
  ///
  /// Token validation is done here in the controller (not in the service layer)
  /// because it is a pure cryptographic check with no database involvement —
  /// ConfirmationTokenService decrypts the AES payload and checks the expiry
  /// timestamp in memory. Only if the token is valid and has purpose "confirm"
  /// does the call proceed to AuthService.ActivateUserAsync, which flips the
  /// account's is_active flag in the database.
  ///
  /// [AllowAnonymous] — the user is not logged in when clicking the email link.
  ///
  /// POST /Auth/confirm-email
  /// </summary>
  [HttpPost("confirm-email")]
  [AllowAnonymous]
  public async Task<IActionResult> ConfirmEmail([FromBody] TokenRequest request) {
    if (string.IsNullOrWhiteSpace(request?.Token))
      return BadRequest(Error("Token is required.", 1));

    var (isValid, email, purpose) = _tokenService.ValidateToken(request.Token);

    if (!isValid || purpose != "confirm")
      return BadRequest(Error(
          "This confirmation link has expired or is invalid. Please register again.", 2));

    var result = await _authService.ActivateUserAsync(email);
    return result.Success ? Ok(result) : BadRequest(result);
  }

  // Login

  /// <summary>
  /// Authenticates the user and returns a JWT access token and refresh token.
  ///
  /// The @identifier field in the request accepts either a username or an
  /// email address — the stored procedure handles both. On success, the
  /// response contains the access token, refresh token, and expiry date.
  ///
  /// Two distinct failure paths:
  ///   ResultCode 1 — wrong credentials  → 401 Unauthorized
  ///   ResultCode 2 — account not yet confirmed → 403 Forbidden
  ///     The 403 (rather than 401) signals to the client that the credentials
  ///     are correct but the account needs confirmation, so the app can show
  ///     a "resend confirmation email" prompt rather than a generic error.
  ///
  /// POST /Auth/login
  /// </summary>
  [HttpPost("login")]
  public async Task<IActionResult> Login([FromBody] LoginRequest request) {
    var result = await _authService.LoginAsync(request, GetDeviceInfo());

    if (!result.Success)
      return result.ResultCode == 2
          ? StatusCode(403, result)   // unconfirmed account — distinct from wrong password
          : Unauthorized(result);

    return Ok(result);
  }

  // Refresh

  /// <summary>
  /// Exchanges a valid refresh token for a new access token and a new refresh
  /// token (token rotation). The old refresh token is invalidated in the
  /// session table by sp_RefreshToken.
  ///
  /// Called by the mobile app when the access token expires. The client stores
  /// the refresh token securely and uses this endpoint transparently to extend
  /// the session without requiring the user to log in again.
  ///
  /// POST /Auth/refresh
  /// </summary>
  [HttpPost("refresh")]
  public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest request) {
    var result = await _authService.RefreshTokenAsync(request.RefreshToken);
    return result.Success ? Ok(result) : Unauthorized(result);
  }

  // Logout

  /// <summary>
  /// Invalidates the current session by marking the JWT in the session table
  /// as inactive. The token is extracted from the Authorization: Bearer header
  /// rather than the request body so the client does not need to cache it
  /// separately from the header it already sends on every request.
  ///
  /// [Authorize] — only authenticated users can log out.
  ///
  /// POST /Auth/logout
  /// </summary>
  [Authorize]
  [HttpPost("logout")]
  public async Task<IActionResult> Logout() {
    var result = await _authService.LogoutAsync(GetTokenFromHeader());
    return Ok(result);
  }

  // Profile

  /// <summary>
  /// Updates the authenticated user's email address and phone number.
  ///
  /// The user ID is read from the JWT claims rather than the request body —
  /// this prevents one user from updating another user's profile by supplying
  /// a different ID. The stored procedure enforces the email uniqueness
  /// constraint and returns a descriptive error if a duplicate is detected.
  ///
  /// [Authorize] — identity is established from the JWT, not from input.
  ///
  /// PUT /Auth/profile
  /// </summary>
  [Authorize]
  [HttpPut("profile")]
  public async Task<IActionResult> UpdateProfile([FromBody] UpdateProfileRequest request) {
    var result = await _authService.UpdateProfileAsync(GetUserId(), request);
    return result.Success ? Ok(result) : BadRequest(result);
  }

  // Change password 

  /// <summary>
  /// Changes the authenticated user's password. Requires the current password
  /// to be supplied alongside the new one — holding a valid JWT is not
  /// sufficient to change the password. This prevents session hijacking from
  /// escalating to a full account takeover.
  ///
  /// The three-step validation (strength → fetch hash → verify old) is handled
  /// entirely in AuthService; this controller just passes the request through.
  ///
  /// [Authorize] — identity is established from the JWT.
  ///
  /// POST /Auth/change-password
  /// </summary>
  [Authorize]
  [HttpPost("change-password")]
  public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest request) {
    var result = await _authService.ChangePasswordAsync(GetUserId(), request);
    return result.Success ? Ok(result) : BadRequest(result);
  }

  // Forgot password 

  /// <summary>
  /// Sends a password reset email to the provided address if an account exists.
  ///
  /// [AllowAnonymous] — the user cannot log in when they've forgotten their password.
  ///
  /// Anti-enumeration design: the endpoint always returns the same success
  /// response regardless of whether the email matches an account. The token
  /// is generated and the email attempted only when the address is non-empty;
  /// any failure (SMTP error, address not found) is swallowed and logged.
  /// The caller sees a generic "if an account exists..." message either way.
  ///
  /// POST /Auth/forgot-password
  /// </summary>
  [HttpPost("forgot-password")]
  [AllowAnonymous]
  public async Task<IActionResult> ForgotPassword([FromBody] EmailRequest request) {
    try {
      if (!string.IsNullOrWhiteSpace(request?.Email)) {
        var token = _tokenService.GeneratePasswordResetToken(request.Email.Trim());
        await _emailService.SendPasswordResetEmailAsync(request.Email.Trim(), token);
      }
    }
    catch (Exception ex) {
      _logger.LogError(ex, "Password reset failed for {Email}", request?.Email);
    }

    return Ok(new ApiResponse<object> {
      Success = true,
      Message = "If an account exists with that email, a password reset link has been sent.",
      ResultCode = 0
    });
  }

  // Reset password

  /// <summary>
  /// Validates the reset token from the email link and sets a new password.
  ///
  /// [AllowAnonymous] — the user is not logged in when clicking the reset link.
  ///
  /// Token validation is done here in the controller (same pattern as
  /// ConfirmEmail) — the token is decrypted in memory by ConfirmationTokenService
  /// before any database call is made. Only if purpose == "reset" and the token
  /// has not expired does the call proceed to AuthService.ResetPasswordByEmailAsync,
  /// which validates password strength and writes the new hash.
  ///
  /// POST /Auth/reset-password
  /// </summary>
  [HttpPost("reset-password")]
  [AllowAnonymous]
  public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request) {
    if (string.IsNullOrWhiteSpace(request?.Token) ||
        string.IsNullOrWhiteSpace(request?.NewPassword))
      return BadRequest(Error("Token and new password are required.", 1));

    var (isValid, email, purpose) = _tokenService.ValidateToken(request.Token);

    if (!isValid || purpose != "reset")
      return BadRequest(Error(
          "This reset link has expired or is invalid. Please request a new password reset.", 2));

    var result = await _authService.ResetPasswordByEmailAsync(email, request.NewPassword);
    return result.Success ? Ok(result) : BadRequest(result);
  }

  // Delete account — request

  /// <summary>
  /// Step 1 of the two-step account deletion flow. Generates a deletion token,
  /// stores it in the database via AuthService, and emails the confirmation
  /// link to the user.
  ///
  /// [AllowAnonymous] — a user may want to delete their account without being
  /// logged in (e.g., they want to delete from a different device).
  ///
  /// Anti-enumeration: always returns the same generic success response.
  /// The email is only sent when AuthService confirms the account exists
  /// (result.Data != null). Any SMTP failure is logged but swallowed.
  ///
  /// The IP address is captured here and passed to AuthService so the stored
  /// procedure can record it in t_account_deletion_requests for audit purposes.
  ///
  /// POST /Auth/delete-account/request
  /// </summary>
  [HttpPost("delete-account/request")]
  [AllowAnonymous]
  public async Task<IActionResult> DeleteAccountRequest([FromBody] EmailRequest request) {
    _logger.LogInformation("Account deletion requested for {Email}", request?.Email);

    try {
      if (!string.IsNullOrWhiteSpace(request?.Email)) {
        var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var result = await _authService.RequestAccountDeletionAsync(
            request.Email.Trim(), ip);

        // Only send email if account was found (result.Data != null)
        if (result.Data != null && !string.IsNullOrEmpty(result.Data.UserEmail)) {
          await _emailService.SendAccountDeletionRequestEmailAsync(
              result.Data.UserEmail,
              result.Data.Token!);
        }
      }
    }
    catch (Exception ex) {
      _logger.LogError(ex, "Delete account request failed for {Email}", request?.Email);
    }

    return Ok(new ApiResponse<object> {
      Success = true,
      Message = "If an account with that email exists, a deletion link has been sent.",
      ResultCode = 0
    });
  }

  // Delete account — confirm

  /// <summary>
  /// Step 2 of the account deletion flow. Validates the deletion token and
  /// permanently anonymises the account via AuthService.ConfirmAccountDeletionAsync.
  ///
  /// [AllowAnonymous] — the user clicks a link from their email; no session exists.
  ///
  /// On success, a goodbye email is sent to the address that was on the account
  /// before anonymisation. The email address is returned by AuthService in
  /// result.Data specifically because it will no longer be in the database after
  /// this call completes. SMTP failure on the goodbye email is logged but does
  /// not reverse the deletion.
  ///
  /// POST /Auth/delete-account/confirm
  /// </summary>
  [HttpPost("delete-account/confirm")]
  [AllowAnonymous]
  public async Task<IActionResult> DeleteAccountConfirm([FromBody] TokenRequest request) {
    if (string.IsNullOrWhiteSpace(request?.Token))
      return BadRequest(Error("Token is required.", 1));

    var result = await _authService.ConfirmAccountDeletionAsync(request.Token);

    if (result.Success && !string.IsNullOrEmpty(result.Data)) {
      try { await _emailService.SendAccountDeletionCompleteEmailAsync(result.Data); }
      catch (Exception ex) {
        _logger.LogError(ex, "Goodbye email failed for {Email}", result.Data);
      }
    }

    return result.Success ? Ok(result) : BadRequest(result);
  }

  // Helpers

  /// <summary>
  /// Extracts the user's numeric ID from the NameIdentifier claim embedded
  /// in the JWT. Returns 0 if the claim is absent or unparseable — in practice
  /// this should never happen on an [Authorize] endpoint because the middleware
  /// would have rejected the request before reaching the action method.
  /// </summary>
  private int GetUserId() {
    var claim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
    return int.TryParse(claim, out var id) ? id : 0;
  }

  /// <summary>
  /// Extracts the raw JWT string from the Authorization: Bearer header.
  /// Returns an empty string if the header is absent or malformed —
  /// sp_LogoutUser will simply find no matching session and return a
  /// non-zero result_code, which the Logout action ignores.
  /// </summary>
  private string GetTokenFromHeader() {
    var auth = Request.Headers["Authorization"].ToString();
    return auth.StartsWith("Bearer ") ? auth[7..] : string.Empty;
  }

  /// <summary>
  /// Builds the device_info string stored in the session record for security
  /// auditing. Concatenates the User-Agent and remote IP separated by '|'.
  /// A null IP (e.g., behind certain proxies) is recorded as-is.
  /// </summary>
  private string GetDeviceInfo() {
    var ua = Request.Headers["User-Agent"].ToString();
    var ip = HttpContext.Connection.RemoteIpAddress?.ToString();
    return $"{ua}|{ip}";
  }

  private static ApiResponse<object> Error(string message, int code) =>
      new() { Success = false, Message = message, ResultCode = code };
}

// Request models
// Defined here because they are small, used only by AuthController, and keeping
// them co-located with the controller avoids a proliferation of single-use files.

public class EmailRequest { public string Email { get; set; } = ""; }
public class TokenRequest { public string Token { get; set; } = ""; }
public class ForgotPasswordRequest : EmailRequest { }
public class ConfirmEmailRequest : TokenRequest { }

public class ResetPasswordRequest {
  public string Token { get; set; } = "";
  public string NewPassword { get; set; } = "";
}
