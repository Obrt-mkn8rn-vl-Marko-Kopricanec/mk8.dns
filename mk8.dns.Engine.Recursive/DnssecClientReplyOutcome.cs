namespace Mk8.Dns.Engine.Recursive;

// Processing dispositions, not Secure/Insecure/Bogus/Indeterminate classification.
public enum DnssecClientReplyOutcome
{
    Encoded = 0,
    Failure = 1,
    Refused = 2,
    Unsupported = 3,
    Malformed = 4,
    Denied = 5,
    Overloaded = 6,
    Closed = 7,
}
