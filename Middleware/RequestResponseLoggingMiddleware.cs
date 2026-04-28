using System.Text;

namespace VexTrainerAPI.Middleware;

/// <summary>
/// Middleware to log HTTP requests and responses for debugging
/// WARNING: Should only be enabled in development - logs sensitive data
/// </summary>
public class RequestResponseLoggingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<RequestResponseLoggingMiddleware> _logger;

    public RequestResponseLoggingMiddleware(RequestDelegate next, ILogger<RequestResponseLoggingMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Log request
        await LogRequest(context);

        // Capture original response body stream
        var originalBodyStream = context.Response.Body;

        try
        {
            using var responseBody = new MemoryStream();
            context.Response.Body = responseBody;

            // Call the next middleware
            await _next(context);

            // Log response
            await LogResponse(context, responseBody);

            // Copy the response back to the original stream
            await responseBody.CopyToAsync(originalBodyStream);
        }
        finally
        {
            context.Response.Body = originalBodyStream;
        }
    }

    private async Task LogRequest(HttpContext context)
    {
        context.Request.EnableBuffering();

        var builder = new StringBuilder();
        builder.AppendLine($"HTTP Request: {context.Request.Method} {context.Request.Path}{context.Request.QueryString}");
        builder.AppendLine($"Headers: {string.Join(", ", context.Request.Headers.Select(h => $"{h.Key}={h.Value}"))}");

        if (context.Request.ContentLength > 0)
        {
            context.Request.Body.Position = 0;
            using var reader = new StreamReader(context.Request.Body, Encoding.UTF8, leaveOpen: true);
            var body = await reader.ReadToEndAsync();
            context.Request.Body.Position = 0;
            builder.AppendLine($"Body: {body}");
        }

        _logger.LogInformation(builder.ToString());
    }

    private async Task LogResponse(HttpContext context, MemoryStream responseBody)
    {
        responseBody.Position = 0;
        var responseText = await new StreamReader(responseBody).ReadToEndAsync();
        responseBody.Position = 0;

        var builder = new StringBuilder();
        builder.AppendLine($"HTTP Response: {context.Response.StatusCode}");
        builder.AppendLine($"Headers: {string.Join(", ", context.Response.Headers.Select(h => $"{h.Key}={h.Value}"))}");
        builder.AppendLine($"Body: {responseText}");

        _logger.LogInformation(builder.ToString());
    }
}

/// <summary>
/// Extension method to add the middleware
/// </summary>
public static class RequestResponseLoggingMiddlewareExtensions
{
    public static IApplicationBuilder UseRequestResponseLogging(this IApplicationBuilder builder)
    {
        return builder.UseMiddleware<RequestResponseLoggingMiddleware>();
    }
}
