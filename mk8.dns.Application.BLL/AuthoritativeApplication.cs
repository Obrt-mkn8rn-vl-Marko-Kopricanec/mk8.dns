using Mk8.Dns.Application.Abstractions;
using Mk8.Dns.Contracts;
using Mk8.Dns.Engine.Authoritative;
using Mk8.Dns.Domain;

namespace Mk8.Dns.Application.BLL;

public sealed class AuthoritativeApplication : IDnsExchange, IApplicationStatusSource
{
    private AuthoritativeCatalog? catalog;
    private readonly IDnsMessageCodec codec;
    private readonly string nodeId;
    private readonly IDnsCookieService? cookies;
    private readonly ITsigService? tsig;
    private readonly IDnsResponseLimiter? limiter;

    public AuthoritativeApplication(AuthoritativeCatalog catalog, IDnsMessageCodec codec, string nodeId)
        : this(catalog, codec, nodeId, null) { }

    public AuthoritativeApplication(AuthoritativeCatalog catalog, IDnsMessageCodec codec, string nodeId, IDnsCookieService? cookies)
        : this(catalog, codec, nodeId, cookies, null) { }

    public AuthoritativeApplication(AuthoritativeCatalog catalog, IDnsMessageCodec codec, string nodeId, IDnsCookieService? cookies, ITsigService? tsig)
        : this(catalog, codec, nodeId, cookies, tsig, null) { }

    public AuthoritativeApplication(AuthoritativeCatalog catalog, IDnsMessageCodec codec, string nodeId, IDnsCookieService? cookies, ITsigService? tsig, IDnsResponseLimiter? limiter)
    {
        ArgumentNullException.ThrowIfNull(catalog);
        ArgumentNullException.ThrowIfNull(codec);
        ArgumentException.ThrowIfNullOrEmpty(nodeId);
        if (catalog.ZoneCount == 0)
            throw new ArgumentException("A serving Application requires a nonempty catalog.", nameof(catalog));
        this.catalog = catalog;
        this.codec = codec;
        this.nodeId = nodeId;
        this.cookies = cookies;
        this.tsig = tsig;
        this.limiter = limiter;
    }

    public AuthoritativeApplication(IDnsMessageCodec codec, string nodeId)
        : this(codec, nodeId, null) { }

    public AuthoritativeApplication(IDnsMessageCodec codec, string nodeId, IDnsCookieService? cookies)
        : this(codec, nodeId, cookies, null) { }

    public AuthoritativeApplication(IDnsMessageCodec codec, string nodeId, IDnsCookieService? cookies, ITsigService? tsig)
        : this(codec, nodeId, cookies, tsig, null) { }

    public AuthoritativeApplication(IDnsMessageCodec codec, string nodeId, IDnsCookieService? cookies, ITsigService? tsig, IDnsResponseLimiter? limiter)
    {
        ArgumentNullException.ThrowIfNull(codec);
        ArgumentException.ThrowIfNullOrEmpty(nodeId);
        this.codec = codec;
        this.nodeId = nodeId;
        this.cookies = cookies;
        this.tsig = tsig;
        this.limiter = limiter;
        catalog = new AuthoritativeCatalog([]);
    }

    internal void ReplaceCatalog(AuthoritativeCatalog replacement) => Volatile.Write(ref catalog, replacement);
    internal void Suspend() => Volatile.Write(ref catalog, null);

    public ValueTask<ApplicationStatus> GetStatusAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var generation = Volatile.Read(ref catalog);
        if (generation is null)
            throw new InvalidOperationException("Authoritative storage requires verified reconciliation.");
        return ValueTask.FromResult(new ApplicationStatus(ProtocolVersion.Current, nodeId, "authoritative-replica", generation.ZoneCount != 0 && cookies?.IsAvailable != false && tsig?.IsAvailable != false, generation.ZoneCount));
    }

    public ValueTask<byte[]> ExchangeAsync(ReadOnlyMemory<byte> message, bool tcp, ReadOnlyMemory<byte> peerAddress, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (message.Length > ushort.MaxValue || peerAddress.Length is not (4 or 16))
            throw new ArgumentException("Invalid DNS exchange bounds.", nameof(message));
        byte[] response;
        var peerProved = false;
        try
        {
            using var transaction = tsig?.Open(message.Span, peerAddress.Span);
            ReadOnlyMemory<byte> request = transaction is null ? message : transaction.GetRequest();
            var generation = Volatile.Read(ref catalog);
            var cookieValidated = false;
            if (transaction?.TsigError is > 0)
                response = codec.EncodeError(request.Span, 9);
            else if (generation is null || cookies?.IsAvailable == false || tsig?.IsAvailable == false)
                response = codec.EncodeError(request.Span, 2);
            else
                response = Process(request.Span, generation, tcp, peerAddress.Span, transaction, ref cookieValidated);
            if (transaction is not null && response.Length != 0)
            {
                response = transaction.Complete(response);
                // Even unauthenticated error metadata must respect the conservative UDP budget.
                if (!tcp && (response.Length > 1232 || transaction.TsigError != 0 && response.Length > 512))
                    response = [];
            }
            // Proof of the return path does not change the exact served-origin signing grants.
            peerProved = cookieValidated || transaction is { TsigError: 0, PeerAllowed: true };
        }
        catch (FormatException)
        {
            response = codec.EncodeError(message.Span, 1);
        }
        catch (NotSupportedException)
        {
            response = codec.EncodeError(message.Span, 4);
        }
        if (!tcp && !peerProved && response.Length != 0 && limiter?.TryAdmit(peerAddress.Span, response.Length) == false)
            response = [];
        return ValueTask.FromResult(response);
    }

    private byte[] Process(ReadOnlySpan<byte> message, AuthoritativeCatalog generation, bool tcp, ReadOnlySpan<byte> peer, ITsigTransaction? transaction, ref bool cookieValidated)
    {
        try
        {
            var query = codec.Decode(message);
            var reserve = transaction?.SignatureBytes ?? 0;
            if (transaction is not null && (!transaction.PeerAllowed || query.Question is { } question
                && (generation.GetZoneOrigin(question.Name, question.Type) is not { } origin || !transaction.Authorizes(origin))))
                return codec.Encode(query, new DnsAnswer(5, false, [], [], []), tcp, [], 512, reserve);
            return Respond(query, generation, tcp, peer, transaction, ref cookieValidated);
        }
        catch (FormatException)
        {
            return codec.EncodeError(message, 1);
        }
        catch (NotSupportedException)
        {
            return codec.EncodeError(message, 4);
        }
    }

    private byte[] Respond(DnsQuery query, AuthoritativeCatalog generation, bool tcp, ReadOnlySpan<byte> peer, ITsigTransaction? transaction, ref bool cookieValidated)
    {
        var reservedBytes = transaction?.SignatureBytes ?? 0;
        if (query.EdnsVersion != 0)
            return codec.Encode(query, new DnsAnswer(16, false, [], [], []), tcp, [], 1232, reservedBytes);
        var option = query.GetCookieWire();
        byte[] responseCookie = [];
        var valid = false;
        if (option is not null && cookies is not null)
        {
            if (option.Length != 8 && option.Length is not (>= 16 and <= 40))
                throw new FormatException("Malformed DNS cookie option length.");
            valid = cookies.Validate(option, peer);
            cookieValidated = valid;
            var issued = cookies.Create(option.AsSpan(0, 8), peer);
            if (issued is null)
                return codec.Encode(query, new DnsAnswer(2, false, [], [], []), tcp, [], 512, reservedBytes);
            responseCookie = issued;
        }
        var prefetch = query.Question is null;
        if (prefetch && cookies is null)
            throw new FormatException("Cookie-only requests require the cookie service.");
        var challenge = option is not null && cookies is not null && !valid && (prefetch ? option.Length != 8 : !tcp);
        var answer = challenge ? new DnsAnswer(23, false, [], [], [])
            : query.Question is { } question ? transaction is null ? generation.Resolve(question) : generation.Resolve(question, transaction.Authorizes)
            : new DnsAnswer(0, false, [], [], []);
        var limit = (ushort)(cookies is null || valid ? 1232 : 512);
        return codec.Encode(query, answer, tcp, responseCookie, limit, reservedBytes);
    }
}
