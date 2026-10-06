using System.Security.Cryptography;
using Mk8.Dns.Application.Abstractions;
using Mk8.Dns.Contracts;
using Mk8.Dns.Domain;

namespace Mk8.Dns.Infrastructure;

public sealed record ManagementGrant(Guid TenantId, Guid ZoneId, DnsName Origin, string Actor, DateTimeOffset Expires, ReadOnlyMemory<byte> CredentialHash);
