namespace Mk8.Dns.Engine.Dnssec;

public enum DnssecAnchorState
{
    AddPending = 0,
    Valid = 1,
    Missing = 2,
    Revoked = 3,
}
