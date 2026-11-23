// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using Declaration = Microsoft.Sbom.Api.PackageDetails.NativeDeclarationSyntax.ProjectDeclaration;

namespace Microsoft.Sbom.Api.PackageDetails;

/// <summary>
/// Accepts entire supported Meson version expressions, never a supported-looking prefix.
/// Control-flow-dependent assignments and project calls are not established facts.
/// </summary>
internal static class NativeMesonProjectReader
{
    private static readonly Regex Assignment = new Regex(@"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(['""].*?['""])\s*(?:#.*)?$");
    private static readonly Regex Mutation = new Regex(@"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*[+\-*/%]?=");
    private static readonly Regex Literal = new Regex(@"^(['""])([^'""]*)\1$");
    private static readonly Regex VersionFile = new Regex(@"^files\s*\(\s*(['""])([^'""]+)\1\s*\)$");
    private static readonly Regex Identifier = new Regex(@"^[A-Za-z_][A-Za-z0-9_]*$");

    internal static Declaration Read(string file, string root)
    {
        var text = File.ReadAllText(file);
        var projectCommands = NativeDeclarationSyntax.Commands(text).Where(command => command.Name == "project").ToArray();
        if (projectCommands.Length != 1)
        {
            return null;
        }

        var variables = new Dictionary<string, string>(StringComparer.Ordinal);
        var depth = 0;
        var lines = text.Split('\n');
        for (var index = 0; index < projectCommands[0].Line - 1; index++)
        {
            var line = lines[index].Trim();
            if (line.StartsWith("endif", StringComparison.Ordinal) || line.StartsWith("endforeach", StringComparison.Ordinal))
            {
                depth = Math.Max(0, depth - 1);
            }

            var mutation = Mutation.Match(lines[index]);
            if (mutation.Success)
            {
                var assignment = Assignment.Match(lines[index]);
                var literal = assignment.Success ? Literal.Match(assignment.Groups[2].Value) : null;
                variables[mutation.Groups[1].Value] = depth == 0 && literal?.Success == true ? literal.Groups[2].Value : null;
            }

            if (Regex.IsMatch(line, @"^(if|foreach)\b"))
            {
                depth++;
            }
        }

        var candidates = new List<Declaration>();
        foreach (var command in projectCommands)
        {
            if (depth != 0)
            {
                return null;
            }

            var arguments = NativeDeclarationSyntax.Arguments(command.Arguments);
            if (arguments.Count == 0)
            {
                continue;
            }

            var nameLiteral = Literal.Match(arguments[0]);
            var name = nameLiteral.Success ? nameLiteral.Groups[2].Value : variables.GetValueOrDefault(arguments[0]);
            var expressions = arguments.Where(argument => Regex.IsMatch(argument, @"^version\s*:")).ToArray();
            if (string.IsNullOrWhiteSpace(name) || expressions.Length != 1)
            {
                continue;
            }

            var expression = expressions[0][(expressions[0].IndexOf(':') + 1)..].Trim();
            var literal = Literal.Match(expression);
            var versionFile = VersionFile.Match(expression);
            string value = null;
            if (literal.Success)
            {
                value = literal.Groups[2].Value;
            }
            else if (versionFile.Success)
            {
                var path = Path.GetFullPath(versionFile.Groups[2].Value, Path.GetDirectoryName(file));
                value = NativeDeclarationSyntax.IsLocalFile(path, root) ? File.ReadAllText(path).Trim() : null;
            }
            else if (Identifier.IsMatch(expression))
            {
                value = variables.GetValueOrDefault(expression);
            }

            if (NativeDeclarationSyntax.IsVersion(value))
            {
                candidates.Add(new Declaration(name, value, file, file, command.Line, "meson.project.version"));
            }
        }

        return candidates.Count == 1 ? candidates[0] : null;
    }
}
