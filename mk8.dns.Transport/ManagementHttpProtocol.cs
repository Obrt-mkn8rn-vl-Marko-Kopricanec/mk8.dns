using System.Globalization;
using System.Text.Json;
using Mk8.Dns.Contracts;

namespace Mk8.Dns.Transport;

public static class ManagementHttpProtocol
{
    public const int MaximumRequestBytes = 2_400_000;
    public const int MaximumReplyBytes = 2_500_000;
    public const string VersionHeader = "X-Mk8-Api-Version";
    public const string Version = "2";

    public static ManagementApiRequest ReadRequest(ReadOnlyMemory<byte> data)
    {
        ValidateJson(data, MaximumRequestBytes);
        return JsonSerializer.Deserialize(data.Span, ManagementHttpJsonContext.Default.ManagementApiRequest)
            ?? throw new JsonException("Empty management request.");
    }

    public static byte[] WriteRequest(ManagementApiRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var data = JsonSerializer.SerializeToUtf8Bytes(request, ManagementHttpJsonContext.Default.ManagementApiRequest);
        if (data.Length > MaximumRequestBytes)
            throw new ArgumentException("Management request exceeds its bound.", nameof(request));
        return data;
    }

    public static byte[] WriteReply(ManagementReply reply)
    {
        ValidateReplyBounds(reply);
        var data = JsonSerializer.SerializeToUtf8Bytes(reply, ManagementHttpJsonContext.Default.ManagementReply);
        if (data.Length > MaximumReplyBytes)
            throw new InvalidDataException("Management reply exceeds its bound.");
        return data;
    }

    public static ManagementReply ReadReply(ReadOnlyMemory<byte> data)
    {
        ValidateJson(data, MaximumReplyBytes);
        var reply = JsonSerializer.Deserialize(data.Span, ManagementHttpJsonContext.Default.ManagementReply)
            ?? throw new JsonException("Empty management reply.");
        ValidateReplyBounds(reply);
        return reply;
    }

    public static byte[] WriteError(string code) => JsonSerializer.SerializeToUtf8Bytes(new ManagementHttpError(code), ManagementHttpJsonContext.Default.ManagementHttpError);

    public static string EncodeCredential(ReadOnlyMemory<byte> credential)
    {
        if (credential.Length != 32)
            throw new ArgumentException("Management credentials contain exactly 32 bytes.", nameof(credential));
        return "Bearer " + EncodeBytes(credential);
    }

    public static byte[] DecodeCredential(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.Length != 50 || !value.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            throw new FormatException("Invalid management credential header.");
        return DecodeBytes(value[7..], 32, 32);
    }

    public static string EncodeOrigin(ReadOnlyMemory<byte> origin)
    {
        if (origin.Length is < 1 or > 255)
            throw new ArgumentException("Invalid origin bound.", nameof(origin));
        return EncodeBytes(origin);
    }

    public static byte[] DecodeOrigin(string origin) => DecodeBytes(origin, 1, 255);

    public static string OperationPath(Guid tenantId, Guid zoneId, Guid operationId, ReadOnlyMemory<byte> origin)
        => string.Create(CultureInfo.InvariantCulture, $"/v2/tenants/{tenantId:D}/zones/{zoneId:D}/operations/{operationId:D}?origin={EncodeOrigin(origin)}");

    public static ManagementRequest BindRequest(ManagementApiRequest body, string action, Guid tenantId, Guid zoneId, Guid operationId, ReadOnlyMemory<byte> credential)
    {
        ArgumentNullException.ThrowIfNull(body);
        if (tenantId == Guid.Empty || zoneId == Guid.Empty || operationId == Guid.Empty || body.Origin.Length is < 1 or > 255 || credential.Length != 32)
            throw new ArgumentException("Invalid management context.", nameof(body));
        var valid = action switch
        {
            "edit" => body.ExpectedRevision >= 0 && body.Records.Count is > 0 and <= 10_000 && body.Changes.Count == 0 && body.Selection.Count == 0,
            "patch" => body.ExpectedRevision >= 0 && body.Records.Count == 0 && body.Changes.Count is > 0 and <= 64 && body.Selection.Count == 0,
            "read" => body.ExpectedRevision is null && body.Records.Count == 0 && body.Changes.Count == 0 && body.Selection.Count is > 0 and <= 64,
            "status" => body.ExpectedRevision is null && body.Records.Count == 0 && body.Changes.Count == 0 && body.Selection.Count == 0,
            "import" => body.ExpectedRevision >= 0 && body.Records.Count == 0 && body.Changes.Count == 0 && body.Selection.Count == 0 && ValidZoneFile(body.ZoneFile),
            "export" => body.ExpectedRevision is null && body.Records.Count == 0 && body.Changes.Count == 0 && body.Selection.Count == 0,
            _ => false,
        };
        if (!valid || action is not "import" && body.ZoneFile is not null)
            throw new ArgumentException("Management action has invalid fields.", nameof(body));
        var bytes = body.Origin.Length;
        foreach (var record in body.Records)
        {
            if (record is null)
                throw new ArgumentException("Missing record.", nameof(body));
            AddBound(ref bytes, record.Owner, record.Data);
        }
        foreach (var change in body.Changes)
        {
            if (change is null || change.Add is null || change.Remove is null || change.Add.Count + change.Remove.Count > 256)
                throw new ArgumentException("Invalid change bounds.", nameof(body));
            AddBound(ref bytes, change.Owner, ReadOnlyMemory<byte>.Empty);
            foreach (var value in change.Add.Concat(change.Remove))
            {
                if (value.Length > ushort.MaxValue)
                    throw new ArgumentException("Invalid RDATA bound.", nameof(body));
                bytes = checked(bytes + value.Length);
                if (bytes > 1_048_576)
                    throw new ArgumentException("Management data exceeds its bound.", nameof(body));
            }
        }
        foreach (var key in body.Selection)
        {
            if (key is null)
                throw new ArgumentException("Missing selector.", nameof(body));
            AddBound(ref bytes, key.Owner, ReadOnlyMemory<byte>.Empty);
        }
        return new ManagementRequest(action, tenantId, zoneId, operationId, body.ExpectedRevision ?? 0, body.Origin, body.Records, credential) { Changes = body.Changes, Selection = body.Selection, ZoneFile = body.ZoneFile };
    }

    private static void AddBound(ref int bytes, ReadOnlyMemory<byte> owner, ReadOnlyMemory<byte> data)
    {
        if (owner.Length is < 1 or > 255 || data.Length > ushort.MaxValue)
            throw new ArgumentException("Invalid record bounds.", nameof(owner));
        bytes = checked(bytes + owner.Length + data.Length);
        if (bytes > 1_048_576)
            throw new ArgumentException("Management data exceeds its bound.", nameof(data));
    }

    public static void VerifyReply(ManagementReply reply, string action, Guid operationId)
    {
        ValidateReplyBounds(reply);
        if (reply.OperationId != operationId || (action is "read" or "export" ? reply.State is not "current" : reply.State is not ("accepted" or "activated"))
            || action is not "read" && reply.Records.Count != 0 || (action is "export" ? !ValidZoneFile(reply.ZoneFile) : reply.ZoneFile is not null))
            throw new InvalidDataException("Invalid management reply context.");
    }

    private static void ValidateReplyBounds(ManagementReply reply)
    {
        if (reply is null || reply.OperationId == Guid.Empty || reply.Revision <= 0 || reply.ContentHash is null || reply.ContentHash.Length != 64
            || reply.ContentHash.Any(character => !Uri.IsHexDigit(character)) || reply.Records.Count > 512 || reply.ZoneFile is not null && !ValidZoneFile(reply.ZoneFile))
            throw new InvalidDataException("Invalid management reply bounds.");
        var bytes = 0;
        foreach (var record in reply.Records)
        {
            if (record is null || record.Owner.Length is < 1 or > 255 || record.Data.Length > ushort.MaxValue)
                throw new InvalidDataException("Invalid management record bounds.");
            bytes = checked(bytes + record.Owner.Length + record.Data.Length);
            if (bytes > 1_048_576)
                throw new InvalidDataException("Management records exceed their bound.");
        }
    }

    private static bool ValidZoneFile(string? text) => text is { Length: > 0 and <= ProtocolVersion.MaximumZoneFileBytes }
        && text.All(character => character is >= ' ' and <= '~' or '\t' or '\r' or '\n');

    private static void ValidateJson(ReadOnlyMemory<byte> data, int maximum)
    {
        if (data.Length is 0 || data.Length > maximum)
            throw new JsonException("Invalid management JSON bounds.");
        var reader = new Utf8JsonReader(data.Span, new JsonReaderOptions { MaxDepth = 32 });
        Stack<HashSet<string>> objects = [];
        var tokens = 0;
        while (reader.Read())
        {
            if (++tokens > 160_000)
                throw new JsonException("Management JSON exceeds its token bound.");
            if (reader.TokenType == JsonTokenType.StartObject)
                objects.Push(new HashSet<string>(StringComparer.Ordinal));
            else if (reader.TokenType == JsonTokenType.EndObject)
                objects.Pop();
            else if (reader.TokenType == JsonTokenType.PropertyName && !objects.Peek().Add(reader.GetString()!))
                throw new JsonException("Duplicate management JSON member.");
        }
    }

    private static string EncodeBytes(ReadOnlyMemory<byte> bytes) => Convert.ToBase64String(bytes.Span).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] DecodeBytes(string value, int minimum, int maximum)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.Length == 0 || value.Length > (maximum * 4 + 2) / 3 || value.Any(character => !(character is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9' or '-' or '_')))
            throw new FormatException("Invalid management base64url value.");
        var padded = value.Replace('-', '+').Replace('_', '/').PadRight((value.Length + 3) / 4 * 4, '=');
        var bytes = Convert.FromBase64String(padded);
        if (bytes.Length < minimum || bytes.Length > maximum || !string.Equals(EncodeBytes(bytes), value, StringComparison.Ordinal))
            throw new FormatException("Noncanonical management base64url value.");
        return bytes;
    }
}
