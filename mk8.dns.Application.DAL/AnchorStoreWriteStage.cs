namespace Mk8.Dns.Application.DAL;

internal enum AnchorStoreWriteStage
{
    GenerationFile, GenerationDirectory, PointerFile, PointerDirectory,
    RetentionFile, RetentionDirectory, RetiredGenerationDeleted, RetiredDirectory,
}
