using System.Net;
using System.Net.Mail;

namespace VexTrainerAPI.Services;

/// <summary>
/// Sends a plain-text error notification email when an unhandled exception
/// occurs in the API. Called fire-and-forget from the exception handler so
/// a failing email send never delays or masks the JSON error response.
///
/// Uses the same Email:* keys as the web project's appsettings.json.
/// </summary>
public static class ErrorNotification
{
    public static async Task SendAsync(
        Exception       exception,
        HttpContext     context,
        IConfiguration  config,
        string          appName = "VexTrainer API")
    {
        var smtpHost     = config["Email:SmtpServer"];
        var fromEmail    = config["Email:FromEmail"];
        var fromPassword = config["Email:FromPassword"];
        var toEmail      = config["Email:FeedbackRecipient"] ?? fromEmail;

        if (string.IsNullOrEmpty(smtpHost) || string.IsNullOrEmpty(fromEmail))
            return; // email not configured — skip silently

        var smtpPort  = int.Parse(config["Email:SmtpPort"] ?? "25");
        var enableSsl = bool.Parse(config["Email:EnableSsl"] ?? "false");

        var subject = $"[{appName}] Unhandled Exception — {exception.GetType().Name}";

        var body = $"""
            Unhandled exception in {appName}
            =====================================
            Time (UTC): {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}
            URL:        {context.Request.Method} {context.Request.Path}{context.Request.QueryString}
            User:       {context.User?.Identity?.Name ?? "anonymous"}
            IP:         {context.Connection.RemoteIpAddress}
            User-Agent: {context.Request.Headers.UserAgent}

            Exception: {exception.GetType().FullName}
            Message:   {exception.Message}

            Stack Trace:
            {exception.StackTrace}

            {(exception.InnerException is not null
                ? $"Inner Exception: {exception.InnerException.Message}\n{exception.InnerException.StackTrace}"
                : "")}
            """;

        using var mail = new MailMessage
        {
            From       = new MailAddress(fromEmail, appName),
            Subject    = subject,
            Body       = body,
            IsBodyHtml = false
        };
        mail.To.Add(toEmail!);

        using var smtp = new SmtpClient(smtpHost, smtpPort)
        {
            EnableSsl   = enableSsl,
            Credentials = new NetworkCredential(fromEmail, fromPassword)
        };

        await smtp.SendMailAsync(mail);
    }
}
