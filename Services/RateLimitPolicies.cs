namespace VexTrainerAPI.Services;

/// <summary>
/// Names of the rate-limiter policies registered in Program.cs.
/// Shared constants so the [EnableRateLimiting] attributes and the
/// registrations cannot drift apart.
/// </summary>
public static class RateLimitPolicies {
  /// <summary>POST /Auth/register — default 5 per hour per IP (RateLimiting:RegisterPerHour).</summary>
  public const string Register = "register";

  /// <summary>POST /Auth/forgot-password — default 5 per hour per IP (RateLimiting:ForgotPasswordPerHour).</summary>
  public const string ForgotPassword = "forgot-password";
}
