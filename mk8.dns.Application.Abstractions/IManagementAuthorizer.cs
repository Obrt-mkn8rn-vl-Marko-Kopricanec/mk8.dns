using Mk8.Dns.Contracts;
using Mk8.Dns.Domain;

namespace Mk8.Dns.Application.Abstractions;

public interface IManagementAuthorizer
{
    string Authorize(ManagementRequest request);
}
