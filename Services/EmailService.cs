using System.Net;
using System.Net.Mail;

namespace VexTrainerAPI.Services;

/// <summary>
/// Sends all transactional emails from the VexTrainer platform via SMTP.
/// Configuration is read from appsettings.json under the Email and Site sections:
///
///   Email:SmtpServer        — hostname (default: smtp.gmail.com)
///   Email:SmtpPort          — port number (default: 587)
///   Email:EnableSsl         — whether to use STARTTLS (default: true)
///   Email:FromEmail         — sender address (required)
///   Email:FromPassword      — SMTP auth password (empty = no auth)
///   Email:FromName          — display name shown as sender (default: VexTrainer)
///   Email:FeedbackRecipient — inbox that receives contact form submissions;
///                             falls back to FromEmail if not set
///   Site:BaseUrl            — root URL used to build confirmation/reset links
///                             (default: https://vextrainer.com)
///
/// All public methods return bool: true if the email was accepted by the SMTP
/// server, false if it failed. Failures are logged at Error level but never
/// thrown — the caller decides whether to surface the failure to the user.
///
/// All user-supplied content (names, messages, email addresses) is passed
/// through WebUtility.HtmlEncode before being placed in HTML bodies to prevent
/// XSS injection in email clients that render HTML.
///
/// Registered as Scoped in Program.cs (one instance per HTTP request).
/// </summary>
public class EmailService {
  private readonly ILogger<EmailService> _logger;

  private readonly string _smtpServer;
  private readonly int _smtpPort;
  private readonly bool _enableSsl;
  private readonly string _fromEmail;
  private readonly string _fromPassword;
  private readonly string _fromName;
  private readonly string _contactRecipient;
  private readonly string _webBaseUrl;

  public EmailService(IConfiguration configuration, ILogger<EmailService> logger) {
    _logger = logger;

    _smtpServer = configuration["Email:SmtpServer"] ?? "smtp.gmail.com";
    _smtpPort = int.Parse(configuration["Email:SmtpPort"] ?? "587");
    _enableSsl = bool.Parse(configuration["Email:EnableSsl"] ?? "true");
    _fromEmail = configuration["Email:FromEmail"] ?? throw new InvalidOperationException("Email:FromEmail not configured");
    _fromPassword = configuration["Email:FromPassword"] ?? string.Empty;
    _fromName = configuration["Email:FromName"] ?? "VexTrainer";
    _contactRecipient = configuration["Email:FeedbackRecipient"] ?? _fromEmail;
    _webBaseUrl = configuration["Site:BaseUrl"] ?? "https://vextrainer.com";
  }

  // ── Email Confirmation ────────────────────────────────────────────────────

  /// <summary>
  /// Sends the "confirm your email address" email to a newly registered user.
  ///
  /// The confirmation link points to the web application's /Auth/Confirm page,
  /// not directly to the API, because confirming via the web provides a visible
  /// success/failure page and handles cookie sign-in after activation.
  ///
  /// The token is URL-encoded before embedding to handle any Base64 characters
  /// that would otherwise be misinterpreted as URL structure. The link is valid
  /// for 24 hours, matching the token expiry set in ConfirmationTokenService.
  ///
  /// The userName is HTML-encoded before insertion to prevent XSS if a
  /// malicious actor registers with a username containing HTML tags.
  /// </summary>
  public async Task<bool> SendEmailConfirmationAsync(
      string toEmail,
      string userName,
      string token) {
    try {
      var confirmUrl = $"{_webBaseUrl}/Auth/Confirm?token={Uri.EscapeDataString(token)}";
      var subject = "VexTrainer — Please confirm your email";

      var body = $@"
<html>
<body style='font-family:Arial,sans-serif;line-height:1.6;color:#333;'>
<div style='max-width:600px;margin:0 auto;padding:20px;'>
    <div style='background:#1565C0;color:white;padding:20px;text-align:center;border-radius:5px 5px 0 0;'>
        <h2 style='margin:0;'>Welcome to VexTrainer!</h2>
    </div>
    <div style='background:#f9f9f9;padding:30px;border-radius:0 0 5px 5px;'>
        <p>Hi {WebUtility.HtmlEncode(userName)},</p>
        <p>Thanks for creating your VexTrainer account. Please confirm your email address
           by clicking the button below. This link is valid for <strong>24 hours</strong>.</p>
        <div style='text-align:center;margin:30px 0;'>
            <a href='{confirmUrl}'
               style='background:#1565C0;color:white;padding:14px 30px;text-decoration:none;
                      border-radius:5px;display:inline-block;font-weight:bold;'>
               Confirm Email Address
            </a>
        </div>
        <p>Or copy and paste this link into your browser:</p>
        <p style='background:white;padding:10px;border:1px solid #ddd;border-radius:3px;
                  word-break:break-all;font-size:13px;'>{confirmUrl}</p>
        <p style='color:#6b7280;font-size:13px;'>
            If you did not create a VexTrainer account you can safely ignore this email.
        </p>
    </div>
    <div style='text-align:center;padding:16px;font-size:12px;color:#888;'>
        <p>&copy; {DateTime.Now.Year} VexTrainer &mdash; vextrainer.com</p>
    </div>
</div>
</body>
</html>";

      await SendEmailAsync(toEmail, subject, body);
      _logger.LogInformation("Confirmation email sent to {Email}", toEmail);
      return true;
    }
    catch (Exception ex) {
      _logger.LogError(ex, "Failed to send confirmation email to {Email}", toEmail);
      return false;
    }
  }

  // ── Password Reset ────────────────────────────────────────────────────────

  /// <summary>
  /// Sends the "reset your password" email after a user submits their email
  /// address on the forgot-password form.
  ///
  /// The reset link points to the web application's /Auth/ResetPassword page.
  /// The token is valid for 1 hour (set in ConfirmationTokenService), which is
  /// reflected in the email body so the user knows the urgency.
  ///
  /// No username is included in this email because the endpoint that triggers
  /// it (POST /Auth/forgot-password) does not look up the user record — it
  /// generates the token from the email address alone to prevent enumeration.
  /// </summary>
  public async Task<bool> SendPasswordResetEmailAsync(
      string toEmail,
      string token) {
    try {
      var resetUrl = $"{_webBaseUrl}/Auth/ResetPassword?token={Uri.EscapeDataString(token)}";
      var subject = "VexTrainer — Password Reset Request";

      var body = $@"
<html>
<body style='font-family:Arial,sans-serif;line-height:1.6;color:#333;'>
<div style='max-width:600px;margin:0 auto;padding:20px;'>
    <div style='background:#1565C0;color:white;padding:20px;text-align:center;border-radius:5px 5px 0 0;'>
        <h2 style='margin:0;'>Password Reset Request</h2>
    </div>
    <div style='background:#f9f9f9;padding:30px;border-radius:0 0 5px 5px;'>
        <p>We received a request to reset the password for your VexTrainer account.</p>
        <p>Click the button below to choose a new password.
           This link is valid for <strong>1 hour</strong>.</p>
        <div style='text-align:center;margin:30px 0;'>
            <a href='{resetUrl}'
               style='background:#1565C0;color:white;padding:14px 30px;text-decoration:none;
                      border-radius:5px;display:inline-block;font-weight:bold;'>
               Reset My Password
            </a>
        </div>
        <p>Or copy and paste this link into your browser:</p>
        <p style='background:white;padding:10px;border:1px solid #ddd;border-radius:3px;
                  word-break:break-all;font-size:13px;'>{resetUrl}</p>
        <p style='color:#6b7280;font-size:13px;'>
            If you did not request a password reset, you can safely ignore this email.
            Your password will remain unchanged.
        </p>
    </div>
    <div style='text-align:center;padding:16px;font-size:12px;color:#888;'>
        <p>&copy; {DateTime.Now.Year} VexTrainer &mdash; vextrainer.com</p>
    </div>
</div>
</body>
</html>";

      await SendEmailAsync(toEmail, subject, body);
      _logger.LogInformation("Password reset email sent to {Email}", toEmail);
      return true;
    }
    catch (Exception ex) {
      _logger.LogError(ex, "Failed to send password reset email to {Email}", toEmail);
      return false;
    }
  }

  // ── Account Deletion ──────────────────────────────────────────────────────

  /// <summary>
  /// Sends step 1 of the account deletion flow: the confirmation email
  /// containing the deletion link.
  ///
  /// The link points to the web application's /Auth/DeleteAccount page rather
  /// than the API directly. This is intentional — the web page handles the
  /// cookie sign-out after deletion completes, which the API cannot do since
  /// it is stateless. The token is valid for 24 hours.
  ///
  /// The red header colour (#b91c1c) distinguishes this email visually from
  /// informational emails (blue header) so the user recognises the gravity
  /// of the action before clicking.
  /// </summary>
  public async Task<bool> SendAccountDeletionRequestEmailAsync(
      string toEmail,
      string token) {
    try {
      var confirmUrl = $"{_webBaseUrl}/Auth/DeleteAccount?token={Uri.EscapeDataString(token)}";
      var subject = "VexTrainer — Account Deletion Request";

      var body = $@"
<html>
<body style='font-family:Arial,sans-serif;line-height:1.6;color:#333;'>
<div style='max-width:600px;margin:0 auto;padding:20px;'>
    <div style='background:#b91c1c;color:white;padding:20px;text-align:center;border-radius:5px 5px 0 0;'>
        <h2 style='margin:0;'>Account Deletion Request</h2>
    </div>
    <div style='background:#f9f9f9;padding:30px;border-radius:0 0 5px 5px;'>
        <p>We received a request to permanently delete your VexTrainer account
           and all associated data.</p>
        <p>To confirm deletion, click the button below.
           This link is valid for <strong>24 hours</strong>.</p>
        <div style='text-align:center;margin:30px 0;'>
            <a href='{confirmUrl}'
               style='background:#b91c1c;color:white;padding:14px 30px;text-decoration:none;
                      border-radius:5px;display:inline-block;font-weight:bold;'>
               Yes, Delete My Account
            </a>
        </div>
        <p>Or copy and paste this link into your browser:</p>
        <p style='background:white;padding:10px;border:1px solid #ddd;border-radius:3px;
                  word-break:break-all;font-size:13px;'>{confirmUrl}</p>
        <p style='color:#6b7280;font-size:13px;'>
            If you did not request account deletion, you can safely ignore this email.
            Your account will not be affected.
        </p>
    </div>
    <div style='text-align:center;padding:16px;font-size:12px;color:#888;'>
        <p>&copy; {DateTime.Now.Year} VexTrainer &mdash; vextrainer.com</p>
    </div>
</div>
</body>
</html>";

      await SendEmailAsync(toEmail, subject, body);
      _logger.LogInformation("Deletion request email sent to {Email}", toEmail);
      return true;
    }
    catch (Exception ex) {
      _logger.LogError(ex, "Failed to send deletion request email to {Email}", toEmail);
      return false;
    }
  }

  /// <summary>
  /// Sends step 2 of the account deletion flow: the goodbye confirmation email.
  ///
  /// Called after AuthService.ConfirmAccountDeletionAsync succeeds. The email
  /// is sent to the address that was on the account before anonymisation, which
  /// is why AuthService returns the deleted email address in its response — once
  /// the account is anonymised the address is no longer in the database.
  ///
  /// This email serves as both a receipt for the user and a last-chance signal
  /// that deletion occurred (in case it was triggered by someone else who had
  /// access to the user's inbox).
  /// </summary>
  public async Task<bool> SendAccountDeletionCompleteEmailAsync(string toEmail) {
    try {
      var subject = "VexTrainer — Your account has been deleted";

      var body = $@"
<html>
<body style='font-family:Arial,sans-serif;line-height:1.6;color:#333;'>
<div style='max-width:600px;margin:0 auto;padding:20px;'>
    <div style='background:#1565C0;color:white;padding:20px;text-align:center;border-radius:5px 5px 0 0;'>
        <h2 style='margin:0;'>Account Deleted</h2>
    </div>
    <div style='background:#f9f9f9;padding:30px;border-radius:0 0 5px 5px;'>
        <p>Your VexTrainer account and all associated data have been permanently deleted.
           This includes your profile, quiz history, lesson progress, and login credentials.</p>
        <p>If you change your mind in the future, you are welcome to create a new account at
           <a href='{_webBaseUrl}'>{_webBaseUrl}</a>.</p>
        <p>Thank you for using VexTrainer.</p>
    </div>
    <div style='text-align:center;padding:16px;font-size:12px;color:#888;'>
        <p>&copy; {DateTime.Now.Year} VexTrainer &mdash; vextrainer.com</p>
    </div>
</div>
</body>
</html>";

      await SendEmailAsync(toEmail, subject, body);
      _logger.LogInformation("Deletion complete email sent to {Email}", toEmail);
      return true;
    }
    catch (Exception ex) {
      _logger.LogError(ex, "Failed to send deletion complete email to {Email}", toEmail);
      return false;
    }
  }

  // ── Contact Us ────────────────────────────────────────────────────────────

  /// <summary>
  /// Forwards a contact form submission to the configured feedback inbox.
  ///
  /// Unlike the other email methods, this one sends to an internal recipient
  /// (_contactRecipient) rather than the user. The message content, user name,
  /// IP address, and user agent are all HTML-encoded before insertion. A
  /// Reply-To header is set to the user's email so the recipient can reply
  /// directly without copy-pasting the address.
  ///
  /// The Diagnostics section (IP address, user agent, detected platform) is
  /// included only when those values are non-null, which is always the case
  /// when called from ContactController but allows the method to be called
  /// from other contexts without dummy values.
  ///
  /// Platform detection (Android / iOS / Windows / macOS) is a simple
  /// user-agent substring match — sufficient for internal triage purposes
  /// but not a security check.
  /// </summary>
  public async Task<bool> SendContactEmailAsync(
      string category,
      string message,
      string userName,
      string userEmail,
      string? ipAddress = null,
      string? userAgent = null) {
    try {
      var sanitizedMessage = WebUtility.HtmlEncode(message);
      var subject = $"VexTrainer Contact: [{category}] from {userName}";

      var deviceSection = (ipAddress != null || userAgent != null) ? $@"
        <div class='section'>
            <h3 style='color:#1565C0;margin-top:0;'>Diagnostics</h3>
            <table>
                <tr><td class='key'>IP Address:</td><td>{WebUtility.HtmlEncode(ipAddress ?? "Unknown")}</td></tr>
                <tr><td class='key'>User Agent:</td><td style='font-size:12px;word-break:break-all;'>{WebUtility.HtmlEncode(userAgent ?? "Unknown")}</td></tr>
                <tr><td class='key'>Platform:</td><td>{DetectPlatform(userAgent)}</td></tr>
            </table>
        </div>" : "";

      var body = $@"
<html>
<head>
    <style>
        body    {{ font-family:Arial,sans-serif;line-height:1.6;color:#333;margin:0;padding:0; }}
        .header {{ background:#1565C0;color:white;padding:20px;text-align:center; }}
        .content{{ padding:20px;background:#f9f9f9; }}
        .section{{ background:white;margin:12px 0;padding:16px;border-radius:6px;border-left:4px solid #1565C0; }}
        .msg-text{{ background:#f5f5f5;padding:16px;border-radius:5px;white-space:pre-wrap;font-size:15px;border:1px solid #ddd;margin:8px 0; }}
        .badge  {{ display:inline-block;background:#1565C0;color:white;padding:3px 10px;border-radius:12px;font-size:13px;font-weight:bold;margin-bottom:6px; }}
        table   {{ width:100%;border-collapse:collapse;margin:8px 0; }}
        td      {{ padding:8px;border-bottom:1px solid #eee; }}
        .key    {{ font-weight:bold;width:120px;color:#555; }}
        .footer {{ text-align:center;padding:16px;font-size:12px;color:#888; }}
    </style>
</head>
<body>
    <div class='header'>
        <h2 style='margin:0;'>📬 New Contact Message</h2>
        <p style='margin:4px 0 0;'>VexTrainer Android App</p>
    </div>
    <div class='content'>
        <div class='section'>
            <span class='badge'>{WebUtility.HtmlEncode(category)}</span>
            <h3 style='color:#1565C0;margin:8px 0 4px;'>Message</h3>
            <div class='msg-text'>{sanitizedMessage}</div>
        </div>
        <div class='section'>
            <h3 style='color:#1565C0;margin-top:0;'>Sender</h3>
            <table>
                <tr><td class='key'>Name:</td><td>{WebUtility.HtmlEncode(userName)}</td></tr>
                <tr><td class='key'>Email:</td><td><a href='mailto:{WebUtility.HtmlEncode(userEmail)}'>{WebUtility.HtmlEncode(userEmail)}</a></td></tr>
                <tr><td class='key'>Sent at:</td><td>{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC</td></tr>
            </table>
        </div>
        {deviceSection}
        <div class='section' style='background:#e8f5e9;border-left-color:#2E7D32;'>
            <p style='margin:0;color:#1B5E20;'>
                💡 <strong>Reply directly to this email</strong> to respond to
                {WebUtility.HtmlEncode(userName)} at
                <a href='mailto:{WebUtility.HtmlEncode(userEmail)}'>{WebUtility.HtmlEncode(userEmail)}</a>.
            </p>
        </div>
    </div>
    <div class='footer'>
        <p>Sent via VexTrainer contact form &mdash; vextrainer.com</p>
        <p>&copy; {DateTime.Now.Year} VexTrainer. All rights reserved.</p>
    </div>
</body>
</html>";

      await SendEmailAsync(_contactRecipient, subject, body, replyTo: userEmail);
      _logger.LogInformation("Contact email sent — category:{Category} from:{Email}", category, userEmail);
      return true;
    }
    catch (Exception ex) {
      _logger.LogError(ex, "Failed to send contact email from {Email}", userEmail);
      return false;
    }
  }

  // ── Helpers ───────────────────────────────────────────────────────────────

  /// <summary>
  /// Infers the sender's platform from the User-Agent string for internal
  /// triage display in contact emails. Not a security check — just a
  /// convenience label for the feedback inbox.
  /// </summary>
  private static string DetectPlatform(string? userAgent) {
    if (string.IsNullOrWhiteSpace(userAgent)) return "Unknown";
    var ua = userAgent.ToLowerInvariant();
    if (ua.Contains("android")) return "Android";
    if (ua.Contains("iphone") || ua.Contains("ipad")) return "iOS";
    if (ua.Contains("windows")) return "Windows";
    if (ua.Contains("mac")) return "macOS";
    return "Other";
  }

  /// <summary>
  /// Core SMTP send method shared by all public email methods.
  ///
  /// A new SmtpClient is created per send (rather than shared) because
  /// SmtpClient does not support concurrent sends and has known issues
  /// when reused across requests in an async context. The per-call cost
  /// is a TCP handshake — acceptable for low-frequency transactional email.
  ///
  /// SMTP credentials are only set when a non-empty password is configured,
  /// allowing unauthenticated relay on internal SMTP servers (e.g., local
  /// development mail catchers like MailHog or Papercut).
  ///
  /// replyTo is optional; when supplied it is added to the Reply-To header
  /// so the recipient can respond directly to the original sender without
  /// the VexTrainer from-address appearing in the reply chain.
  /// </summary>
  private async Task SendEmailAsync(
      string to,
      string subject,
      string htmlBody,
      string? replyTo = null) {
    using var client = new SmtpClient(_smtpServer, _smtpPort);
    client.EnableSsl = _enableSsl;
    client.DeliveryMethod = SmtpDeliveryMethod.Network;
    client.UseDefaultCredentials = false;
    if (!string.IsNullOrWhiteSpace(_fromPassword))
      client.Credentials = new NetworkCredential(_fromEmail, _fromPassword);

    using var message = new MailMessage();
    message.From = new MailAddress(_fromEmail, _fromName);
    message.To.Add(to);
    message.Subject = subject;
    message.Body = htmlBody;
    message.IsBodyHtml = true;

    if (!string.IsNullOrWhiteSpace(replyTo))
      message.ReplyToList.Add(new MailAddress(replyTo));

    await client.SendMailAsync(message);
  }
}
