// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using Microsoft.Sbom.Contracts;
using Declaration = Microsoft.Sbom.Api.PackageDetails.NativeDeclarationSyntax.ProjectDeclaration;

namespace Microsoft.Sbom.Api.PackageDetails;

/// <summary>
/// Reads explicit native project declarations without configuring, building, or executing source code.
/// Unsupported evaluation boundaries are unknown facts, never guessed release versions.
/// </summary>
public class NativeBuildPackageDetector : INativeBuildPackageDetector
{
    /// <summary>
    /// Finds source-declared package identities. Owning project location is part of identity;
    /// a shared version include is provenance, not a replacement for project identity.
    /// </summary>
    /// <param name="sourceRoot">Root of the source tree to inspect without executing it.</param>
    /// <returns>Unambiguous source-declared packages with declaration and owning-project locations.</returns>
    public IReadOnlyList<SbomPackage> Detect(string sourceRoot)
    {
        var result = new List<SbomPackage>();
        if (string.IsNullOrWhiteSpace(sourceRoot) || !Directory.Exists(sourceRoot))
        {
            return result;
        }

        sourceRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(sourceRoot));
        var directories = new Stack<string>();
        directories.Push(sourceRoot);
        while (directories.Count > 0)
        {
            var directory = directories.Pop();
            foreach (var entry in Directory.EnumerateFileSystemEntries(directory))
            {
                var attributes = File.GetAttributes(entry);
                if ((attributes & FileAttributes.ReparsePoint) != 0 || Path.GetFileName(entry) == ".git")
                {
                    continue;
                }

                if ((attributes & FileAttributes.Directory) != 0)
                {
                    directories.Push(entry);
                    continue;
                }

                Declaration declaration = null;
                if (Path.GetFileName(entry) == "CMakeLists.txt")
                {
                    declaration = new NativeCmakeProjectReader(entry, sourceRoot).Read();
                }
                else if (Path.GetFileName(entry) == "meson.build")
                {
                    declaration = NativeMesonProjectReader.Read(entry, sourceRoot);
                }

                if (declaration != null)
                {
                    result.Add(ToPackage(declaration, sourceRoot));
                }
            }
        }

        return result;
    }

    private static SbomPackage ToPackage(Declaration declaration, string root)
    {
        var relative = Path.GetRelativePath(root, declaration.File).Replace(Path.DirectorySeparatorChar, '/');
        var project = Path.GetRelativePath(root, declaration.OwnerFile).Replace(Path.DirectorySeparatorChar, '/');
        var source = RepositorySource(Path.GetDirectoryName(declaration.OwnerFile), root);
        var vcsQualifier = source == null ? string.Empty : $"&vcs_url={Uri.EscapeDataString(source)}";
        var qualifiers = $"source_file={Uri.EscapeDataString(relative)}&source_line={declaration.Line.ToString(CultureInfo.InvariantCulture)}&source_project={Uri.EscapeDataString(project)}{vcsQualifier}&version_key={Uri.EscapeDataString(declaration.Key)}";
        return new SbomPackage
        {
            Id = $"native:{project}:{declaration.Name}:{declaration.Value}",
            PackageName = declaration.Name,
            PackageVersion = declaration.Value,
            PackageUrl = $"pkg:generic/{Uri.EscapeDataString(declaration.Name)}@{Uri.EscapeDataString(declaration.Value)}?{qualifiers}",
            PackageSource = source,
            FilesAnalyzed = false,
            Type = "native-source",
        };
    }

    private static string RepositorySource(string directory, string root)
    {
        for (var current = directory; current != null && current.StartsWith(root, StringComparison.Ordinal); current = Path.GetDirectoryName(current))
        {
            var git = Path.Join(current, ".git");
            if (File.Exists(git))
            {
                var pointer = File.ReadAllText(git).Trim();
                if (!pointer.StartsWith("gitdir:", StringComparison.Ordinal))
                {
                    return null;
                }

                git = Path.GetFullPath(pointer["gitdir:".Length..].Trim(), current);
            }

            if (!Directory.Exists(git))
            {
                continue;
            }

            var headFile = Path.Join(git, "HEAD");
            var configFile = Path.Join(git, "config");
            if (!File.Exists(headFile) || !File.Exists(configFile))
            {
                return null;
            }

            var revision = File.ReadAllText(headFile).Trim();
            if (revision.StartsWith("ref: ", StringComparison.Ordinal))
            {
                var reference = revision["ref: ".Length..];
                var loose = Path.Join(git, reference);
                revision = File.Exists(loose) ? File.ReadAllText(loose).Trim() : null;
                var packed = Path.Join(git, "packed-refs");
                if (revision == null && File.Exists(packed))
                {
                    revision = File.ReadLines(packed).FirstOrDefault(line => line.EndsWith(" " + reference, StringComparison.Ordinal))?.Split(' ')[0];
                }
            }

            string remote = null;
            var origin = false;
            foreach (var line in File.ReadLines(configFile))
            {
                var trimmed = line.Trim();
                if (trimmed.StartsWith('['))
                {
                    origin = trimmed == "[remote \"origin\"]";
                }
                else if (origin && trimmed.StartsWith("url", StringComparison.Ordinal) && trimmed.Contains('='))
                {
                    remote = trimmed[(trimmed.IndexOf('=') + 1)..].Trim();
                    break;
                }
            }

            if (remote != null && revision != null && Regex.IsMatch(revision, "^[a-fA-F0-9]{40,64}$") && Uri.TryCreate(remote, UriKind.Absolute, out var uri) && uri.Scheme is "https" or "http" or "ssh" or "git")
            {
                return $"git+{remote}@{revision}";
            }

            return null;
        }

        return null;
    }
}
