// ContactController.cs
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using VexTrainer.Data.Models;
using VexTrainerAPI.Models.Requests;
using VexTrainerAPI.Services;

namespace VexTrainerAPI.Controllers;

/// <summary>
/// Handles contact form submissions from the Android app. This is the only
/// controller that performs meaningful input validation directly in the action
/// method — it does so because there is no stored procedure or service layer to
/// delegate to. EmailService.SendContactEmailAsync is purely an SMTP delivery
/// method with no validation of its own, so the controller must own the rules.
///
/// The user's identity (name, email) is read exclusively from their JWT claims
/// rather than from the request body. This prevents users from spoofing the
/// sender identity and keeps the request model small (only category + message).
///
/// Allowed categories are defined in a static HashSet for O(1) case-insensitive
/// lookup. Adding a new category requires only updating this set.
///
/// Endpoint summary:
///   POST /Contact        — submit a contact message  [Authorize]
///   GET  /Contact/test   — health check              [AllowAnonymous]
/// </summary>
[ApiController]
[Route("[controller]")]
[Authorize]
public class ContactController : ControllerBase {
  private readonly EmailService _emailService;
  private readonly ILogger<ContactController> _logger;

  private static readonly HashSet<string> AllowedCategories =
      new(StringComparer.OrdinalIgnoreCase) { "Suggestion", "Correction", "Other" };

  public ContactController(
      EmailService emailService,
      ILogger<ContactController> logger) {
    _emailService = emailService;
    _logger = logger;
  }

  /// <summary>
  /// Validates and forwards a contact form submission to the configured
  /// feedback inbox via EmailService.
  ///
  /// Validation performed here (not in a service layer) because there is no
  /// database operation — the rules are simple enough to live in the controller:
  ///   - request body must not be null
  ///   - category must be one of the allowed values (case-insensitive)
  ///   - message must be between 10 and 2000 characters
  ///
  /// The sender's name and email are read from JWT claims (ClaimTypes.Name and
  /// ClaimTypes.Email respectively), falling back to safe defaults if a claim
  /// is absent. The IP address and user agent are captured from the HTTP context
  /// and included in the email body for internal triage purposes.
  ///
  /// Returns 500 if the SMTP delivery fails, giving the client a signal to
  /// retry or inform the user. This is the one place in the API that returns
  /// a 500 from a controller action rather than letting unhandled exceptions
  /// propagate to the global error handler.
  ///
  /// POST /Contact
  /// </summary>
  [HttpPost]
  public async Task<IActionResult> Submit([FromBody] ContactRequest request) {
    var userName = User.FindFirstValue(ClaimTypes.Name)
                 ?? User.FindFirstValue("unique_name")
                 ?? "VexTrainer User";
    var userEmail = User.FindFirstValue(ClaimTypes.Email)
                 ?? User.FindFirstValue("email")
                 ?? "";

    var ipAddress = Request.HttpContext.Connection.RemoteIpAddress?.ToString();
    var userAgent = Request.Headers["User-Agent"].ToString();

    _logger.LogInformation(
        "Contact submission from {User} <{Email}> — category: {Category} — IP: {IP}",
        userName, userEmail, request?.Category, ipAddress);

    if (request is null)
      return BadRequest(new ApiResponse<object> {
        Success = false,
        Message = "Invalid request.",
        ResultCode = 1
      });

    if (string.IsNullOrWhiteSpace(request.Category) ||
        !AllowedCategories.Contains(request.Category))
      return BadRequest(new ApiResponse<object> {
        Success = false,
        Message = "Category must be Suggestion, Correction, or Other.",
        ResultCode = 2
      });

    var message = request.Message?.Trim() ?? "";

    if (message.Length < 10)
      return BadRequest(new ApiResponse<object> {
        Success = false,
        Message = "Message must be at least 10 characters.",
        ResultCode = 3
      });

    if (message.Length > 2000)
      return BadRequest(new ApiResponse<object> {
        Success = false,
        Message = "Message must not exceed 2000 characters.",
        ResultCode = 4
      });

    var sent = await _emailService.SendContactEmailAsync(
        category: request.Category,
        message: message,
        userName: userName,
        userEmail: userEmail,
        ipAddress: ipAddress,
        userAgent: userAgent);

    if (sent) {
      _logger.LogInformation("Contact email delivered from {Email}", userEmail);
      return Ok(new ApiResponse<object> {
        Success = true,
        Message = "Thank you! Your message has been sent.",
        ResultCode = 0
      });
    }

    _logger.LogError("Contact email failed from {Email}", userEmail);
    return StatusCode(500, new ApiResponse<object> {
      Success = false,
      Message = "Failed to send your message. Please try again later.",
      ResultCode = 99
    });
  }

  /// <summary>
  /// Lightweight health check confirming the Contact service is reachable.
  /// [AllowAnonymous] so monitoring tools can call it without a JWT.
  ///
  /// GET /Contact/test
  /// </summary>
  [HttpGet("test")]
  [AllowAnonymous]
  public IActionResult Test() =>
      Ok(new ApiResponse<object> {
        Success = true,
        Data = new { service = "Contact", status = "Active", timestamp = DateTime.UtcNow },
        Message = "Contact service is operational",
        ResultCode = 0
      });
}
