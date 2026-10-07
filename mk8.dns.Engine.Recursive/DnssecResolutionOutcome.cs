namespace Mk8.Dns.Engine.Recursive;

public enum DnssecResolutionOutcome
{
    Failure = 0,
    Authenticated = 1,
    UnsignedDelegation = 2,
}
