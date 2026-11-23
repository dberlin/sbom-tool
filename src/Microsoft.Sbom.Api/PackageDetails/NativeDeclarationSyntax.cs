// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace Microsoft.Sbom.Api.PackageDetails;

/// <summary>
/// Lexical boundaries shared by the conservative source-declaration readers.
/// Bracket contents are never interpreted as commands or variable expressions.
/// </summary>
internal static class NativeDeclarationSyntax
{
    private static readonly Regex VersionPattern = new Regex(@"^\d+(?:\.\d+){0,3}(?:[-+~][0-9A-Za-z.-]+)?$");
    private const string OpaqueArgument = "$<unsupported-bracket-argument>";

    internal static bool IsVersion(string value) => value != null && VersionPattern.IsMatch(value);

    internal static bool IsLocalFile(string file, string root)
    {
        if (!file.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.Ordinal) || !File.Exists(file))
        {
            return false;
        }

        for (var current = file; current != root; current = Path.GetDirectoryName(current))
        {
            if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
            {
                return false;
            }
        }

        return true;
    }

    internal static IEnumerable<Command> Commands(string text)
    {
        var index = 0;
        var line = 1;
        while (index < text.Length)
        {
            SkipWhitespaceAndComments(text, ref index, ref line);
            if (index >= text.Length)
            {
                yield break;
            }

            if (text[index] is '\'' or '"')
            {
                Advance(text, ref index, ref line, QuotedEnd(text, index));
                continue;
            }

            if (BracketEnd(text, index, out var opaqueEnd))
            {
                Advance(text, ref index, ref line, opaqueEnd);
                continue;
            }

            if (!char.IsLetter(text[index]) && text[index] != '_')
            {
                index++;
                continue;
            }

            var start = index++;
            var startLine = line;
            while (index < text.Length && (char.IsLetterOrDigit(text[index]) || text[index] == '_'))
            {
                index++;
            }

            var name = text[start..index].ToLowerInvariant();
            SkipWhitespaceAndComments(text, ref index, ref line);
            if (index >= text.Length || text[index] != '(')
            {
                continue;
            }

            index++;
            var depth = 1;
            var arguments = new StringBuilder();
            while (index < text.Length && depth > 0)
            {
                var character = text[index];
                if (character is '\'' or '"')
                {
                    var end = QuotedEnd(text, index);
                    arguments.Append(text.AsSpan(index, end - index));
                    Advance(text, ref index, ref line, end);
                }
                else if (BracketEnd(text, index, out var end))
                {
                    arguments.Append(text.AsSpan(index, end - index));
                    Advance(text, ref index, ref line, end);
                }
                else if (character == '#')
                {
                    SkipComment(text, ref index, ref line);
                    arguments.Append(' ');
                }
                else if (character == '\\' && index + 1 < text.Length)
                {
                    arguments.Append(text.AsSpan(index, 2));
                    Advance(text, ref index, ref line, index + 2);
                }
                else
                {
                    index++;
                    if (character == '\n')
                    {
                        line++;
                    }

                    if (character == '(')
                    {
                        depth++;
                    }
                    else if (character == ')')
                    {
                        depth--;
                    }

                    if (depth > 0)
                    {
                        arguments.Append(character);
                    }
                }
            }

            if (depth == 0)
            {
                yield return new Command(name, arguments.ToString(), startLine);
            }
        }
    }

    internal static List<string> Tokens(string arguments) => Tokenize(arguments, false, out _);

    internal static List<string> Tokens(string arguments, out List<int> listExpansions) => Tokenize(arguments, true, out listExpansions);

    private static List<string> Tokenize(string arguments, bool captureExpansions, out List<int> listExpansions)
    {
        listExpansions = null;
        var result = new List<string>();
        var token = new StringBuilder();
        var started = false;
        var expandsList = false;
        var quote = '\0';
        for (var index = 0; index < arguments.Length; index++)
        {
            var character = arguments[index];
            if (quote != '\0')
            {
                if (character == quote)
                {
                    quote = '\0';
                }
                else if (character == '\\' && index + 1 < arguments.Length && (arguments[index + 1] == '\\' || arguments[index + 1] == quote))
                {
                    token.Append(arguments[++index]);
                }
                else
                {
                    token.Append(character);
                }
            }
            else if (character == '"')
            {
                quote = character;
                started = true;
            }
            else if (BracketEnd(arguments, index, out var end))
            {
                token.Append(OpaqueArgument);
                started = true;
                index = end - 1;
            }
            else if (char.IsWhiteSpace(character))
            {
                if (started)
                {
                    if (captureExpansions && expandsList)
                    {
                        (listExpansions ??= new List<int>()).Add(result.Count);
                    }

                    result.Add(token.ToString());
                    token.Clear();
                    started = false;
                    expandsList = false;
                }
            }
            else
            {
                expandsList |= captureExpansions && character is '$' or ';';
                token.Append(character);
                started = true;
            }
        }

        if (started)
        {
            if (captureExpansions && expandsList)
            {
                (listExpansions ??= new List<int>()).Add(result.Count);
            }

            result.Add(token.ToString());
        }

        return result;
    }

    internal static IReadOnlyList<string> Arguments(string arguments)
    {
        var result = new List<string>();
        var start = 0;
        var depth = 0;
        for (var index = 0; index < arguments.Length; index++)
        {
            var character = arguments[index];
            if (character is '\'' or '"')
            {
                index = QuotedEnd(arguments, index) - 1;
            }
            else if (character is '(' or '[' or '{')
            {
                depth++;
            }
            else if (character is ')' or ']' or '}')
            {
                depth--;
            }
            else if (character == ',' && depth == 0)
            {
                result.Add(arguments[start..index].Trim());
                start = index + 1;
            }
        }

        result.Add(arguments[start..].Trim());
        return result;
    }

    private static int QuotedEnd(string text, int start)
    {
        var quote = text[start];
        if (start + 2 < text.Length && text[start + 1] == quote && text[start + 2] == quote)
        {
            var closing = text.IndexOf(new string(quote, 3), start + 3, StringComparison.Ordinal);
            return closing < 0 ? text.Length : closing + 3;
        }

        for (var index = start + 1; index < text.Length; index++)
        {
            if (text[index] == '\\')
            {
                index++;
            }
            else if (text[index] == quote)
            {
                return index + 1;
            }
        }

        return text.Length;
    }

    private static bool BracketEnd(string text, int start, out int end)
    {
        end = start;
        if (text[start] != '[')
        {
            return false;
        }

        var index = start + 1;
        while (index < text.Length && text[index] == '=')
        {
            index++;
        }

        if (index >= text.Length || text[index] != '[')
        {
            return false;
        }

        var closing = "]" + new string('=', index - start - 1) + "]";
        var found = text.IndexOf(closing, index + 1, StringComparison.Ordinal);
        end = found < 0 ? text.Length : found + closing.Length;
        return true;
    }

    private static void SkipWhitespaceAndComments(string text, ref int index, ref int line)
    {
        while (index < text.Length)
        {
            if (text[index] == '#')
            {
                SkipComment(text, ref index, ref line);
            }
            else if (char.IsWhiteSpace(text[index]))
            {
                if (text[index++] == '\n')
                {
                    line++;
                }
            }
            else
            {
                break;
            }
        }
    }

    private static void SkipComment(string text, ref int index, ref int line)
    {
        index++;
        if (index < text.Length && BracketEnd(text, index, out var end))
        {
            Advance(text, ref index, ref line, end);
            return;
        }

        while (index < text.Length && text[index] != '\n')
        {
            index++;
        }
    }

    private static void Advance(string text, ref int index, ref int line, int end)
    {
        while (index < end)
        {
            if (text[index++] == '\n')
            {
                line++;
            }
        }
    }

    internal sealed record ProjectDeclaration(string Name, string Value, string OwnerFile, string File, int Line, string Key);

    internal sealed record Command(string Name, string Arguments, int Line);
}
