namespace Mk8.Dns.Wire;

internal static class MasterFileTokens
{
    internal static IEnumerable<MasterFileEntry> Read(string text)
    {
        List<MasterFileToken> tokens = [];
        var grouped = false;
        var leading = false;
        var reuse = false;
        var totalTokens = 0;
        for (var position = 0; position < text.Length;)
        {
            var character = text[position];
            if (character is ' ' or '\t')
            {
                if (tokens.Count == 0)
                    leading = true;
                position++;
                continue;
            }
            if (character is ';')
            {
                while (position < text.Length && text[position] is not ('\r' or '\n'))
                    position++;
                continue;
            }
            if (character is '\r' or '\n')
            {
                position++;
                if (!grouped)
                {
                    if (tokens.Count != 0)
                        yield return new MasterFileEntry(tokens.ToArray(), reuse);
                    tokens.Clear();
                    leading = false;
                }
                continue;
            }
            if (character is '(' or ')')
            {
                Require(character == '(' ? !grouped && tokens.Count != 0 : grouped);
                grouped = character == '(';
                position++;
                continue;
            }
            if (tokens.Count == 0)
                reuse = leading;
            var token = ReadToken(text, ref position);
            Require(++totalTokens <= 160_000 && token.Text.Length <= 131_070);
            tokens.Add(token);
        }
        Require(!grouped);
        if (tokens.Count != 0)
            yield return new MasterFileEntry(tokens.ToArray(), reuse);
    }

    private static MasterFileToken ReadToken(string text, ref int position)
    {
        var quoted = text[position] == '"';
        if (quoted)
            position++;
        var start = position;
        while (position < text.Length)
        {
            var character = text[position];
            if (character == '\\')
            {
                Require(position + 1 < text.Length && text[position + 1] is not ('\r' or '\n'));
                position += 2;
                continue;
            }
            if (quoted ? character == '"' : character is ' ' or '\t' or '\r' or '\n' or ';' or '(' or ')')
                break;
            Require(quoted || character != '"');
            position++;
        }
        var token = text[start..position];
        if (quoted)
        {
            Require(position < text.Length && text[position++] == '"');
            Require(position == text.Length || text[position] is ' ' or '\t' or '\r' or '\n' or ';' or '(' or ')');
        }
        return new MasterFileToken(token, quoted);
    }

    private static void Require(bool condition)
    {
        if (!condition)
            throw new FormatException("Invalid master-file token or grouping.");
    }
}
