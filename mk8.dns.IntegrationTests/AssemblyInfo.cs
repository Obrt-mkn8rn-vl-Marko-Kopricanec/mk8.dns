using Xunit;

// Keep fsync-heavy development clusters sequential; tests still create concurrent requests explicitly.
[assembly: CollectionBehavior(DisableTestParallelization = true)]
