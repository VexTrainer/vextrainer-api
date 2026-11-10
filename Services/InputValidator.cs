using System.Net.Mail;
using System.Text;
using System.Text.RegularExpressions;

namespace VexTrainerAPI.Services;

/// <summary>
/// Server-side validation for user-supplied identity fields (Full Name, email).
///
/// Client-side checks in the apps are not a security boundary — bots call the
/// API directly — so every endpoint that accepts these fields must run them
/// through this class before passing them to the data layer.
///
/// Note: the DB/DTO field is called "UserName" but it holds the user's Full Name
/// (the UI labels it "Full Name").
///
/// Error message strings are part of the client contract (the Android app shows
/// the same text) — do not reword them without updating the apps.
/// </summary>
public static class InputValidator {
  public const int MaxNameLength = 50;
  public const int MaxEmailLength = 254;   // RFC 5321 path limit

  public const string NameRequiredMessage = "Name is required.";
  public const string NameTooLongMessage = "Name must be 50 characters or fewer.";
  public const string NameInvalidMessage =
      "Name can only contain letters, spaces, hyphens, apostrophes, periods and commas.";
  public const string EmailInvalidMessage = "Enter a valid email address.";
  public const string EmailDisposableMessage =
      "Disposable email addresses are not allowed. Please use a permanent email address.";

  // Letters in any script (each optionally followed by combining marks), joined
  // by at most one separator: space, hyphen, apostrophe (' or ’), or ". " / ", ".
  // A period must be followed by a space or end the name, so "example.com" fails.
  // \z (not $) so a trailing "\n" cannot sneak through.
  private static readonly Regex NameRegex = new(
      @"^\p{L}\p{M}*(?:(?:[.,] |[ '’\-])?\p{L}\p{M}*)*\.?\z",
      RegexOptions.CultureInvariant,
      TimeSpan.FromMilliseconds(250));

  private static readonly Regex WhitespaceRun = new(@"\s+", RegexOptions.CultureInvariant);

  // Pragmatic address shape: no whitespace/angle brackets/quotes, one '@',
  // and a dotted domain made of LDH labels with an alphabetic-ish TLD.
  private static readonly Regex EmailRegex = new(
      @"^[^\s@<>()\[\]\\,;:""]+@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z][A-Za-z0-9-]{0,61}[A-Za-z0-9]\z",
      RegexOptions.CultureInvariant,
      TimeSpan.FromMilliseconds(250));

  private static readonly Lazy<HashSet<string>> DisposableDomains = new(LoadDisposableDomains);

  // ── Name ─────────────────────────────────────────────────────────────────

  /// <summary>
  /// Trims, collapses whitespace runs to a single space and applies Unicode
  /// NFC normalisation (so "é" typed as e + combining accent is stored the
  /// same as the precomposed form). Returns "" for null.
  /// </summary>
  public static string NormalizeName(string? name) {
    if (name is null) return string.Empty;
    var collapsed = WhitespaceRun.Replace(name.Trim(), " ");
    return collapsed.Normalize(NormalizationForm.FormC);
  }

  /// <summary>
  /// Normalises and validates a Full Name. On success returns (true, normalised, null);
  /// on failure returns (false, normalised, error message).
  /// </summary>
  public static (bool IsValid, string Normalized, string? Error) ValidateFullName(string? name) {
    var normalized = NormalizeName(name);

    if (normalized.Length == 0)
      return (false, normalized, NameRequiredMessage);

    if (normalized.Length > MaxNameLength)
      return (false, normalized, NameTooLongMessage);

    bool matches;
    try { matches = NameRegex.IsMatch(normalized); }
    catch (RegexMatchTimeoutException) { matches = false; }

    return matches
        ? (true, normalized, null)
        : (false, normalized, NameInvalidMessage);
  }

  // ── Email ────────────────────────────────────────────────────────────────

  /// <summary>
  /// Trims and validates an email address's format, then rejects domains (and
  /// subdomains of domains) on the bundled disposable-email blocklist.
  /// </summary>
  public static (bool IsValid, string Normalized, string? Error) ValidateEmail(string? email) {
    var normalized = (email ?? string.Empty).Trim();

    if (!IsValidEmailFormat(normalized))
      return (false, normalized, EmailInvalidMessage);

    var domain = normalized[(normalized.LastIndexOf('@') + 1)..];
    if (IsDisposableDomain(domain))
      return (false, normalized, EmailDisposableMessage);

    return (true, normalized, null);
  }

  public static bool IsValidEmailFormat(string email) {
    if (string.IsNullOrEmpty(email) || email.Length > MaxEmailLength)
      return false;

    bool matches;
    try { matches = EmailRegex.IsMatch(email); }
    catch (RegexMatchTimeoutException) { return false; }
    if (!matches) return false;

    var at = email.LastIndexOf('@');
    if (at > 64) return false;                       // local part ≤ 64 chars
    var local = email[..at];
    if (local.StartsWith('.') || local.EndsWith('.') || local.Contains(".."))
      return false;

    // Final cross-check with the framework parser (also what SmtpClient uses).
    return MailAddress.TryCreate(email, out var parsed) &&
           string.Equals(parsed.Address, email, StringComparison.Ordinal);
  }

  /// <summary>
  /// True if the domain, or any parent domain (e.g. "x.fextemp.com" → "fextemp.com"),
  /// is on the disposable-email blocklist.
  /// </summary>
  public static bool IsDisposableDomain(string domain) {
    var set = DisposableDomains.Value;
    var d = domain.Trim().TrimEnd('.').ToLowerInvariant();
    while (true) {
      if (set.Contains(d)) return true;
      var dot = d.IndexOf('.');
      if (dot < 0) return false;
      d = d[(dot + 1)..];
      if (!d.Contains('.')) return false;           // stop at bare TLD
    }
  }

  /// <summary>
  /// Loads Resources/disposable_email_blocklist.conf (embedded in the assembly).
  /// Source: https://github.com/disposable-email-domains/disposable-email-domains
  /// To refresh, re-download disposable_email_blocklist.conf from that repo and rebuild.
  /// </summary>
  private static HashSet<string> LoadDisposableDomains() {
    var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    var asm = typeof(InputValidator).Assembly;
    var resourceName = asm.GetManifestResourceNames()
        .FirstOrDefault(n => n.EndsWith("disposable_email_blocklist.conf", StringComparison.OrdinalIgnoreCase));
    if (resourceName is null) return set;

    using var stream = asm.GetManifestResourceStream(resourceName)!;
    using var reader = new StreamReader(stream);
    string? line;
    while ((line = reader.ReadLine()) != null) {
      line = line.Trim();
      if (line.Length == 0 || line.StartsWith('#')) continue;
      set.Add(line);
    }
    return set;
  }
}
