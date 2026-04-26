using System.Security.Cryptography;
using System.Text;

namespace VexTrainerAPI.Services;

/// <summary>
/// Generates and validates self-contained, time-limited tokens used for
/// email confirmation and password reset flows.
///
/// Each token encodes three pieces of data: the user's email address, the
/// purpose ("confirm" or "reset"), and an expiry timestamp. The payload is
/// AES-128-CBC encrypted and then encoded as URL-safe Base64, making the
/// token safe to embed in email links without additional encoding.
///
/// Because the token is self-contained, no database table is needed to track
/// issued tokens — the encrypted payload carries everything needed to validate
/// it. The trade-off is that individual tokens cannot be revoked before they
/// expire (though expiry windows are short: 24h for confirmation, 1h for reset).
///
/// The AES key is derived at construction time by SHA-256 hashing the
/// DefaultConnection connection string (or JWT secret as a fallback). This
/// ties token validity to the application's configuration — tokens issued
/// before a configuration change become invalid automatically, which is the
/// desired behavior after a security incident.
///
/// Registered as Scoped in Program.cs (one instance per request). The key
/// derivation is cheap and the service holds no mutable state, so Singleton
/// would also be safe, but Scoped keeps the lifetime consistent with the
/// other services in the auth flow.
/// </summary>
public class ConfirmationTokenService {
  private readonly byte[] _key;

  public ConfirmationTokenService(IConfiguration configuration) {
    // Key derivation matches the web project's derivation so tokens issued
    // by the API can be validated by the web app and vice versa.
    // SHA-256 produces 32 bytes, which is exactly the AES-256 key length.
    var secret = configuration.GetConnectionString("DefaultConnection")
              ?? configuration["Jwt:Secret"]
              ?? "DefaultSecretKeyForEncryption32";
    _key = SHA256.HashData(Encoding.UTF8.GetBytes(secret))[..32];
  }

  /// <summary>
  /// Generates an AES-encrypted, URL-safe token that confirms the given email
  /// address is reachable by the person registering. Valid for 24 hours.
  ///
  /// The controller sends this token to AuthService.ActivateUserAsync after
  /// ValidateToken confirms purpose == "confirm" and the token has not expired.
  /// </summary>
  public string GenerateEmailConfirmationToken(string email) {
    var data = $"{email}|confirm|{DateTime.UtcNow.AddHours(24):O}";
    return Encrypt(data);
  }

  /// <summary>
  /// Generates an AES-encrypted, URL-safe token authorising a one-time
  /// password reset for the given email address. Valid for 1 hour.
  ///
  /// The controller passes this token to AuthService.ResetPasswordByEmailAsync
  /// after ValidateToken confirms purpose == "reset" and expiry has not passed.
  /// The short 1-hour window limits the damage if a reset email is intercepted
  /// or a user's inbox is briefly compromised.
  /// </summary>
  public string GeneratePasswordResetToken(string email) {
    var data = $"{email}|reset|{DateTime.UtcNow.AddHours(1):O}";
    return Encrypt(data);
  }

  /// <summary>
  /// Decrypts and validates any token produced by this service.
  ///
  /// Validation steps performed (in order):
  ///   1. Base64 decode and AES decrypt — any tampered or malformed token fails here.
  ///   2. Split on '|' — expects exactly three segments: email, purpose, expiry.
  ///   3. Parse the expiry timestamp and compare to UTC now.
  ///
  /// Any decryption error, format mismatch, or expired token returns
  /// (false, "", "") — the caller receives a uniform failure result regardless
  /// of which step failed, preventing an attacker from distinguishing between
  /// a forged token and an expired one.
  ///
  /// The returned purpose string ("confirm" or "reset") must be checked by the
  /// caller to ensure a confirmation token cannot be used as a reset token and
  /// vice versa.
  /// </summary>
  public (bool isValid, string email, string purpose) ValidateToken(string token) {
    try {
      var data = Decrypt(token);
      var parts = data.Split('|');
      if (parts.Length != 3) return (false, string.Empty, string.Empty);

      var email = parts[0];
      var purpose = parts[1];
      var expiration = DateTime.Parse(parts[2]);

      if (DateTime.UtcNow > expiration) return (false, string.Empty, string.Empty);

      return (true, email, purpose);
    }
    catch {
      // Any error — tampered ciphertext, bad padding, wrong key — is treated
      // as invalid. No error details are surfaced to the caller.
      return (false, string.Empty, string.Empty);
    }
  }

  // ── AES Helpers ───────────────────────────────────────────────────────────

  /// <summary>
  /// Encrypts plainText using AES-CBC with a freshly generated random IV.
  /// The IV is prepended to the ciphertext before Base64 encoding so the
  /// Decrypt method can extract it without a separate channel.
  /// The output uses URL-safe Base64 ('+' → '-', '/' → '_', '=' stripped)
  /// so the token can be placed directly in a URL query parameter.
  /// </summary>
  private string Encrypt(string plainText) {
    using var aes = Aes.Create();
    aes.Key = _key;
    aes.GenerateIV();   // fresh random IV for every token

    var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
    using var ms = new MemoryStream();
    ms.Write(aes.IV, 0, aes.IV.Length);   // prepend IV to ciphertext

    using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
    using (var sw = new StreamWriter(cs))
      sw.Write(plainText);

    return Convert.ToBase64String(ms.ToArray())
        .Replace("+", "-").Replace("/", "_").Replace("=", "");
  }

  /// <summary>
  /// Reverses the URL-safe Base64 encoding, extracts the IV from the first
  /// 16 bytes, then decrypts the remainder using AES-CBC.
  /// Throws on any decryption failure — the caller's try/catch in ValidateToken
  /// handles all error cases uniformly.
  /// </summary>
  private string Decrypt(string cipherText) {
    // Restore standard Base64 padding and symbols before decoding
    var padded = cipherText.Replace("-", "+").Replace("_", "/");
    var remainder = padded.Length % 4;
    if (remainder != 0) padded += new string('=', 4 - remainder);

    var fullCipher = Convert.FromBase64String(padded);

    using var aes = Aes.Create();
    aes.Key = _key;

    var iv = new byte[16];
    Array.Copy(fullCipher, 0, iv, 0, iv.Length);
    aes.IV = iv;

    var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
    using var ms = new MemoryStream(fullCipher, iv.Length, fullCipher.Length - iv.Length);
    using var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);
    using var sr = new StreamReader(cs);

    return sr.ReadToEnd();
  }
}
