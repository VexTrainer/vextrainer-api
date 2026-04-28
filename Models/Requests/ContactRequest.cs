namespace VexTrainerAPI.Models.Requests;

/// <summary>
/// Request model for the Contact Us form.
/// UserName and UserEmail are not sent by the client — they are read
/// from the JWT claims on the server for security.
/// </summary>
public class ContactRequest
{
    /// <summary>
    /// Category chosen by the user. Must be one of: Suggestion, Correction, Other.
    /// </summary>
    public string Category { get; set; } = "Suggestion";

    /// <summary>
    /// The message body (10–2000 characters, required).
    /// </summary>
    public string Message { get; set; } = string.Empty;
}
