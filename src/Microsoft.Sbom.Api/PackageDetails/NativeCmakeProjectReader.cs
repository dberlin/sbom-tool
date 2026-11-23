// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using Command = Microsoft.Sbom.Api.PackageDetails.NativeDeclarationSyntax.Command;
using Declaration = Microsoft.Sbom.Api.PackageDetails.NativeDeclarationSyntax.ProjectDeclaration;

namespace Microsoft.Sbom.Api.PackageDetails;

/// <summary>
/// A bounded declaration reader, not a CMake interpreter. Unknown control flow taints
/// affected facts; called user-defined writes are invalidated rather than executed.
/// </summary>
internal sealed class NativeCmakeProjectReader
{
    private static readonly Regex Variable = new Regex(@"\$\{([^}]+)\}");
    private readonly string owner;
    private readonly string root;
    private readonly string sourceDirectory;
    private readonly Dictionary<string, Fact> variables = new Dictionary<string, Fact>(StringComparer.Ordinal);
    private readonly Dictionary<string, List<Definition>> definitions = new Dictionary<string, List<Definition>>(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> names = new HashSet<string>(StringComparer.Ordinal);
    private readonly HashSet<string> activeIncludes = new HashSet<string>(StringComparer.Ordinal);
    private readonly List<Declaration> candidates = new List<Declaration>();
    private bool unresolvedDeclaration;
    private string versionAlias;

    internal NativeCmakeProjectReader(string owner, string root)
    {
        this.owner = owner;
        this.root = root;
        sourceDirectory = Path.GetDirectoryName(owner);
        variables["CMAKE_CURRENT_SOURCE_DIR"] = new Fact(true, sourceDirectory);
        variables["CMAKE_MODULE_PATH"] = new Fact(true, string.Empty);
    }

    internal Declaration Read()
    {
        Visit(owner, 0, true);
        if (unresolvedDeclaration || names.Count != 1)
        {
            return null;
        }

        var name = names.Single();
        var exact = candidates.Where(candidate => candidate.Name == name).ToArray();
        return exact.Select(candidate => candidate.Value).Distinct(StringComparer.Ordinal).Count() == 1 ? exact[0] : null;
    }

    private void Visit(string file, int depth, bool? inheritedMode)
    {
        if (inheritedMode == false || !NativeDeclarationSyntax.IsLocalFile(file, root))
        {
            return;
        }

        if (depth > 16 || !activeIncludes.Add(file))
        {
            unresolvedDeclaration = true;
            return;
        }

        var previousListDirectory = variables.GetValueOrDefault("CMAKE_CURRENT_LIST_DIR");
        variables["CMAKE_CURRENT_LIST_DIR"] = new Fact(true, Path.GetDirectoryName(file));
        var commands = NativeDeclarationSyntax.Commands(File.ReadAllText(file)).ToList();
        var conditions = new Stack<Conditional>();
        var mode = inheritedMode;
        for (var index = 0; index < commands.Count; index++)
        {
            var command = commands[index];
            var tokens = NativeDeclarationSyntax.Tokens(command.Arguments, out var listExpansions);
            if (command.Name is "macro" or "function")
            {
                var start = index + 1;
                var nesting = 1;
                while (++index < commands.Count && nesting > 0)
                {
                    if (commands[index].Name is "macro" or "function")
                    {
                        nesting++;
                    }
                    else if (commands[index].Name is "endmacro" or "endfunction")
                    {
                        nesting--;
                    }
                }

                if (tokens.Count > 0 && nesting == 0)
                {
                    if (mode != false)
                    {
                        var definition = new Definition(tokens.Skip(1).ToArray(), commands.GetRange(start, index - start - 1));
                        if (mode == true || !definitions.TryGetValue(tokens[0], out var alternatives))
                        {
                            definitions[tokens[0]] = new List<Definition> { definition };
                        }
                        else
                        {
                            // An unknown branch may leave the earlier definition
                            // active. Retain every possible body's write effects.
                            alternatives.Add(definition);
                        }
                    }

                    index--;
                }
                else
                {
                    unresolvedDeclaration = true;
                }

                continue;
            }

            if (command.Name is "while" or "foreach")
            {
                // A proven false while body never executes. All other loop
                // writes are unestablished: iteration evaluation is out of scope.
                var neverRuns = mode == false || (command.Name == "while" && Condition(tokens, null) == false);
                conditions.Push(new Conditional(mode, null));
                mode = neverRuns ? false : null;
                if (!neverRuns)
                {
                    // Iterators can change the names targeted by body writes.
                    // No pre-loop variable value is safe evidence across this
                    // unsupported evaluation boundary.
                    ForgetFacts();
                    if (command.Name == "foreach" && tokens.Count > 0 && IsVersionAlias(tokens[0]))
                    {
                        Set(tokens[0], null, null, false, file, command.Line, "foreach");
                    }
                }

                continue;
            }

            if (command.Name == "if")
            {
                var condition = mode == false ? false : Condition(tokens, mode);
                conditions.Push(new Conditional(mode, Not(condition)));
                mode = And(mode, condition);
                continue;
            }

            if (command.Name is "elseif" or "else")
            {
                if (conditions.Count == 0)
                {
                    unresolvedDeclaration = true;
                    continue;
                }

                var branch = conditions.Pop();
                var available = And(branch.Parent, branch.Remaining);
                var condition = command.Name == "else" ? true : available == false ? false : Condition(tokens, available);
                mode = And(available, condition);
                conditions.Push(new Conditional(branch.Parent, And(branch.Remaining, Not(condition))));
                continue;
            }

            if (command.Name is "endif" or "endwhile" or "endforeach")
            {
                if (conditions.TryPop(out var branch))
                {
                    mode = branch.Parent;
                }
                else
                {
                    unresolvedDeclaration = true;
                }

                continue;
            }

            if (mode == false)
            {
                continue;
            }

            if (definitions.ContainsKey(command.Name) && command.Name != "rocm_setup_version")
            {
                IReadOnlyList<string> arguments = StableArity(tokens, listExpansions, null, int.MaxValue) ? tokens : Array.Empty<string>();
                InvalidateCall(command.Name, arguments, new HashSet<string>(StringComparer.OrdinalIgnoreCase));
                continue;
            }

            if (tokens.Count == 0)
            {
                continue;
            }

            var proofThrough = command.Name is "project" or "rocm_setup_version" ? int.MaxValue : command.Name == "file" ? 2 : 0;
            if ((command.Name is "project" or "rocm_setup_version" or "set" or "unset" or "option" or "include" or "file") && !StableArity(tokens, listExpansions, null, proofThrough))
            {
                InvalidateFacts();
                unresolvedDeclaration |= command.Name is "project" or "rocm_setup_version";
                continue;
            }

            if (command.Name == "set")
            {
                var key = Expand(tokens[0]);
                if (key != null)
                {
                    var end = tokens.FindIndex(1, token => token.Equals("CACHE", StringComparison.OrdinalIgnoreCase) || token.Equals("PARENT_SCOPE", StringComparison.OrdinalIgnoreCase));
                    end = end < 0 ? tokens.Count : end;
                    var value = end <= 1 ? null : Expand(string.Join(";", tokens.Skip(1).Take(end - 1)));
                    Set(key, value, mode, end <= 1, file, command.Line, "set." + key);
                }
                else
                {
                    InvalidateFacts();
                }
            }
            else if (command.Name == "unset")
            {
                var key = Expand(tokens[0]);
                if (key != null)
                {
                    Set(key, null, mode, true, file, command.Line, "unset");
                }
                else
                {
                    InvalidateFacts();
                }
            }
            else if (command.Name == "option")
            {
                Set(tokens[0], null, null, false, file, command.Line, "option");
            }
            else if (command.Name == "list" && tokens.Count >= 3 && tokens[1] == "CMAKE_MODULE_PATH" && (tokens[0].Equals("APPEND", StringComparison.OrdinalIgnoreCase) || tokens[0].Equals("PREPEND", StringComparison.OrdinalIgnoreCase)))
            {
                var previous = Value("CMAKE_MODULE_PATH");
                var paths = Expand(string.Join(";", tokens.Skip(2)));
                var value = previous == null || paths == null ? null : tokens[0].Equals("APPEND", StringComparison.OrdinalIgnoreCase) ? previous + ";" + paths : paths + ";" + previous;
                Set("CMAKE_MODULE_PATH", value, mode, false, file, command.Line, "list");
            }
            else if (command.Name == "file" && tokens.Count == 3 && tokens[0].Equals("READ", StringComparison.OrdinalIgnoreCase))
            {
                var path = Expand(tokens[1]);
                path = path == null ? null : Path.GetFullPath(path, sourceDirectory);
                var value = path != null && NativeDeclarationSyntax.IsLocalFile(path, root) ? File.ReadAllText(path).Trim() : null;
                Set(tokens[2], value, mode, false, file, command.Line, "file.READ");
            }
            else if (command.Name == "include")
            {
                var include = Include(Expand(tokens[0]));
                if (include != null)
                {
                    Visit(include, depth + 1, mode);
                }
                else
                {
                    // No host-module or nearby-file guesses. Unavailable inputs
                    // cannot establish variable values or scoped export proofs.
                    foreach (var key in variables.Keys.Where(key => !key.StartsWith("CMAKE_CURRENT_", StringComparison.Ordinal) && key != "PROJECT_NAME").ToArray())
                    {
                        variables[key] = new Fact(null, null);
                    }
                }
            }
            else if (command.Name == "string")
            {
                Transform(tokens, listExpansions, mode, file, command.Line);
            }
            else if (command.Name == "cmake_language")
            {
                if (StableArity(tokens, listExpansions, null, int.MaxValue))
                {
                    InvalidateLanguageCall(tokens, null, new HashSet<string>(StringComparer.OrdinalIgnoreCase));
                }
                else
                {
                    InvalidateFacts();
                }
            }
            else if (command.Name is "list" or "math" or "file")
            {
                InvalidateWrites(command.Name, tokens, null, file, command.Line, listExpansions);
            }
            else if (command.Name == "project")
            {
                var name = Expand(tokens[0]);
                if (mode != true || string.IsNullOrWhiteSpace(name))
                {
                    unresolvedDeclaration = true;
                }
                else
                {
                    names.Add(name);
                    versionAlias = name + "_VERSION";
                    variables["PROJECT_NAME"] = new Fact(true, name);
                    AddVersion(name, tokens, file, command.Line, "project.VERSION");
                }
            }
            else if (command.Name == "rocm_setup_version" && names.Count == 1)
            {
                if (mode == true)
                {
                    AddVersion(names.Single(), tokens, file, command.Line, "rocm_setup_version");
                }
                else
                {
                    unresolvedDeclaration = true;
                }
            }
            else
            {
                InvalidateWrites(command.Name, tokens, null, file, command.Line, listExpansions);
            }
        }

        if (conditions.Count != 0)
        {
            unresolvedDeclaration = true;
        }

        variables["CMAKE_CURRENT_LIST_DIR"] = previousListDirectory;
        activeIncludes.Remove(file);
    }

    private string Include(string include)
    {
        if (string.IsNullOrEmpty(include))
        {
            return null;
        }

        if (Path.IsPathRooted(include) || include.Contains('/') || include.Contains('\\') || include.EndsWith(".cmake", StringComparison.OrdinalIgnoreCase))
        {
            var file = Path.GetFullPath(include, sourceDirectory);
            return NativeDeclarationSyntax.IsLocalFile(file, root) ? file : null;
        }

        var paths = Value("CMAKE_MODULE_PATH");
        if (paths == null)
        {
            return null;
        }

        foreach (var path in paths.Split(';', StringSplitOptions.RemoveEmptyEntries))
        {
            var file = Path.GetFullPath(Path.Join(path, include + ".cmake"), sourceDirectory);
            if (File.Exists(file))
            {
                return NativeDeclarationSyntax.IsLocalFile(file, root) ? file : null;
            }
        }

        return null;
    }

    private void Set(string name, string value, bool? mode, bool unset, string file, int line, string key)
    {
        if (mode == false)
        {
            return;
        }

        name = Expand(name);
        if (name == null || name.Contains(';'))
        {
            InvalidateFacts();
            return;
        }

        variables[name] = mode == null ? new Fact(null, null) : unset ? new Fact(false, null) : new Fact(true, value);
        if (names.Count == 1 && IsVersionAlias(name))
        {
            if (mode == true && !unset && NativeDeclarationSyntax.IsVersion(value))
            {
                candidates.Add(new Declaration(names.Single(), value, owner, file, line, key));
            }
            else
            {
                unresolvedDeclaration = true;
            }
        }
    }

    private void AddVersion(string name, IReadOnlyList<string> tokens, string file, int line, string key)
    {
        for (var index = 0; index + 1 < tokens.Count; index++)
        {
            if (tokens[index].Equals("VERSION", StringComparison.OrdinalIgnoreCase))
            {
                var value = Expand(tokens[index + 1]);
                if (NativeDeclarationSyntax.IsVersion(value))
                {
                    candidates.Add(new Declaration(name, value, owner, file, line, key));
                    variables["PROJECT_VERSION"] = new Fact(true, value);
                    variables[versionAlias] = new Fact(true, value);
                }
                else
                {
                    unresolvedDeclaration = true;
                }
            }
        }
    }

    private void Transform(IReadOnlyList<string> tokens, List<int> listExpansions, bool? mode, string file, int line)
    {
        if (!NativeCmakeWriteEffects.TryTarget("string", tokens, out _, out var position) || !StableArity(tokens, listExpansions, null, position))
        {
            InvalidateFacts();
            return;
        }

        if (tokens.Count == 3 && tokens[0].Equals("STRIP", StringComparison.OrdinalIgnoreCase))
        {
            Set(tokens[2], Expand(tokens[1])?.Trim(), mode, false, file, line, "string.STRIP");
        }
        else if (tokens.Count == 6 && tokens[0].Equals("REGEX", StringComparison.OrdinalIgnoreCase) && tokens[1].Equals("REPLACE", StringComparison.OrdinalIgnoreCase))
        {
            var pattern = Expand(tokens[2]);
            var replacement = Expand(tokens[3]);
            var value = Expand(tokens[5]);
            string transformed = null;
            if (pattern != null && replacement != null && value != null && !pattern.Contains("(?", StringComparison.Ordinal))
            {
                try
                {
                    replacement = Regex.Replace(replacement, @"\\([0-9])", match => "${" + match.Groups[1].Value + "}");
                    transformed = Regex.Replace(value, pattern, replacement, RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(200));
                }
                catch (ArgumentException)
                {
                    // Unsupported source expressions cannot establish a version.
                }
                catch (RegexMatchTimeoutException)
                {
                    // Source data never authorizes unbounded regex evaluation.
                }
            }

            Set(tokens[4], transformed, mode, false, file, line, "string.REGEX_REPLACE");
        }
        else
        {
            InvalidateWrites("string", tokens, null, file, line, listExpansions);
        }
    }

    private bool? Condition(IReadOnlyList<string> tokens, bool? mode)
    {
        if (tokens.Count > 0 && tokens[0].Equals("NOT", StringComparison.OrdinalIgnoreCase))
        {
            return Not(Condition(tokens.Skip(1).ToArray(), mode));
        }

        if (tokens.Count == 2 && tokens[0].Equals("DEFINED", StringComparison.OrdinalIgnoreCase))
        {
            return variables.TryGetValue(tokens[1], out var fact) ? fact.Defined : null;
        }

        if (tokens.Count == 1)
        {
            var literal = Boolean(tokens[0]);
            if (literal.HasValue)
            {
                return literal;
            }

            if (variables.TryGetValue(tokens[0], out var fact))
            {
                return fact.Defined == false ? false : fact.Value == null ? null : Boolean(fact.Value);
            }
        }

        if (tokens.Count == 3 && tokens[1].Equals("MATCHES", StringComparison.OrdinalIgnoreCase))
        {
            for (var index = 0; index <= 9; index++)
            {
                variables["CMAKE_MATCH_" + index.ToString(CultureInfo.InvariantCulture)] = new Fact(mode == true ? false : null, null);
            }

            var value = tokens[0].Contains("${", StringComparison.Ordinal) ? Expand(tokens[0]) : Value(tokens[0]);
            var pattern = Expand(tokens[2]);
            if (value != null && pattern != null && !pattern.Contains("(?", StringComparison.Ordinal))
            {
                try
                {
                    var match = Regex.Match(value, pattern, RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(200));
                    if (match.Success)
                    {
                        for (var index = 0; index < Math.Min(10, match.Groups.Count); index++)
                        {
                            variables["CMAKE_MATCH_" + index.ToString(CultureInfo.InvariantCulture)] = new Fact(mode, mode == true ? match.Groups[index].Value : null);
                        }
                    }

                    return match.Success;
                }
                catch (ArgumentException)
                {
                    return null;
                }
                catch (RegexMatchTimeoutException)
                {
                    return null;
                }
            }
        }

        return null;
    }

    private void InvalidateCall(string name, IReadOnlyList<string> arguments, HashSet<string> active, Dictionary<string, string> inheritedBindings = null)
    {
        if (!definitions.TryGetValue(name, out var alternatives) || !active.Add(name))
        {
            // Recursive arguments can select different output variables. Do not
            // reuse any tracked fact across an unresolved call boundary.
            InvalidateFacts();
            ClearBindings(inheritedBindings);
            return;
        }

        foreach (var definition in alternatives)
        {
            var bindings = inheritedBindings == null ? new Dictionary<string, string>(StringComparer.Ordinal) : new Dictionary<string, string>(inheritedBindings, StringComparer.Ordinal);
            for (var index = 0; index < definition.Parameters.Count; index++)
            {
                bindings[definition.Parameters[index]] = index < arguments.Count ? Expand(arguments[index]) : null;
            }

            foreach (var command in definition.Body)
            {
                var tokens = NativeDeclarationSyntax.Tokens(command.Arguments, out var listExpansions);
                if (command.Name is "foreach" or "while")
                {
                    ForgetFacts();
                    if (command.Name == "foreach" && tokens.Count > 0)
                    {
                        bindings[tokens[0]] = null;
                        if (IsVersionAlias(tokens[0]))
                        {
                            Set(tokens[0], null, null, false, owner, command.Line, "foreach");
                        }
                    }
                }

                if (command.Name == "project" || command.Name == "rocm_setup_version")
                {
                    unresolvedDeclaration = true;
                }
                else if (definitions.ContainsKey(command.Name))
                {
                    var nestedArguments = StableArity(tokens, listExpansions, bindings, int.MaxValue) ? tokens.Select(token => Expand(token, bindings)).ToArray() : Array.Empty<string>();
                    InvalidateCall(command.Name, nestedArguments, active, bindings);
                }
                else if (command.Name == "cmake_language")
                {
                    if (StableArity(tokens, listExpansions, bindings, int.MaxValue))
                    {
                        InvalidateLanguageCall(tokens, bindings, active);
                    }
                    else
                    {
                        InvalidateFacts();
                        ClearBindings(bindings);
                    }
                }
                else if (tokens.Count > 0)
                {
                    InvalidateWrites(command.Name, tokens, bindings, owner, command.Line, listExpansions);
                }
            }

            if (inheritedBindings != null)
            {
                foreach (var binding in bindings)
                {
                    if (binding.Value == null && inheritedBindings.ContainsKey(binding.Key))
                    {
                        inheritedBindings[binding.Key] = null;
                    }
                }
            }
        }

        active.Remove(name);
    }

    private void InvalidateLanguageCall(IReadOnlyList<string> tokens, Dictionary<string, string> bindings, HashSet<string> active)
    {
        if (tokens.Count < 2 || !tokens[0].Equals("CALL", StringComparison.OrdinalIgnoreCase))
        {
            InvalidateFacts();
            ClearBindings(bindings);
            return;
        }

        var text = tokens[1];
        var pattern = new StringBuilder("^");
        var position = 0;
        foreach (Match variable in Variable.Matches(text))
        {
            pattern.Append(Regex.Escape(text[position..variable.Index]));
            var name = variable.Groups[1].Value;
            var value = bindings != null && bindings.TryGetValue(name, out var bound) ? bound : Value(name);
            pattern.Append(value == null ? ".*" : Regex.Escape(value));
            position = variable.Index + variable.Length;
        }

        pattern.Append(Regex.Escape(text[position..])).Append('$');
        var possible = new Regex(pattern.ToString(), RegexOptions.CultureInvariant | RegexOptions.IgnoreCase | RegexOptions.NonBacktracking, TimeSpan.FromMilliseconds(200));
        var matched = false;
        if (!possible.IsMatch("project") && !possible.IsMatch("rocm_setup_version"))
        {
            foreach (var name in definitions.Keys)
            {
                if (possible.IsMatch(name))
                {
                    matched = true;
                    InvalidateCall(name, tokens.Skip(2).Select(token => Expand(token, bindings)).ToArray(), active, bindings);
                }
            }
        }

        if (!matched)
        {
            InvalidateFacts();
            ClearBindings(bindings);
        }
    }

    private static void ClearBindings(Dictionary<string, string> bindings)
    {
        if (bindings != null)
        {
            foreach (var key in bindings.Keys.ToArray())
            {
                bindings[key] = null;
            }
        }
    }

    private void InvalidateWrites(string command, IReadOnlyList<string> tokens, Dictionary<string, string> bindings, string file, int line, List<int> listExpansions)
    {
        var known = NativeCmakeWriteEffects.TryTarget(command, tokens, out var target, out var position);
        var prefixIndex = command == "cmake_parse_arguments" && tokens[0].Equals("PARSE_ARGV", StringComparison.OrdinalIgnoreCase) ? 2 : 0;
        var prefixWrite = command is "cmake_parse_arguments" or "find_package";
        var hasOptions = command is "execute_process" or "file" || (command == "list" && tokens[0] == "TRANSFORM");
        var proofThrough = prefixWrite ? prefixIndex : hasOptions ? int.MaxValue : position;
        if (!StableArity(tokens, listExpansions, bindings, proofThrough))
        {
            InvalidateFacts();
            ClearBindings(bindings);
            return;
        }

        // A same-variable export preserves metadata only when every version
        // alias is still known in this scope. Local/parameter shadows and any
        // earlier possible version mutation disqualify that proof.
        var identityCopy = command == "set" && (tokens.Count == 2 || (tokens.Count == 3 && tokens[2].Equals("PARENT_SCOPE", StringComparison.OrdinalIgnoreCase))) && tokens[1] == "${" + tokens[0] + "}";
        var expandedTarget = identityCopy ? Expand(tokens[0], bindings) : null;
        if (identityCopy && expandedTarget?.Contains(';') != true && VersionAliasesUnchanged(bindings))
        {
            ForgetFacts();
            ClearBindings(bindings);
            return;
        }

        if (command is "cmake_parse_arguments" or "find_package")
        {
            // Prefix output names are supported only after proving argument arity.
            var prefix = prefixIndex < tokens.Count ? Expand(tokens[prefixIndex], bindings) : null;
            if (prefix == null)
            {
                InvalidateFacts();
                ClearBindings(bindings);
            }
            else
            {
                prefix += "_";
                foreach (var key in variables.Keys.Where(key => key.StartsWith(prefix, StringComparison.Ordinal)).ToArray())
                {
                    Set(key, null, null, false, file, line, "unsupported-prefix-write");
                }

                if (bindings != null)
                {
                    foreach (var key in bindings.Keys.Where(key => key.StartsWith(prefix, StringComparison.Ordinal)).ToArray())
                    {
                        bindings[key] = null;
                    }
                }
            }

            return;
        }

        for (var index = 0; index + 1 < tokens.Count; index++)
        {
            if (NativeCmakeWriteEffects.IsOptionOutput(command, tokens[index]))
            {
                InvalidateTarget(tokens[index + 1], bindings, file, line);
            }
        }

        if (!known)
        {
            InvalidateFacts();
            ClearBindings(bindings);
        }
        else if (target != null)
        {
            InvalidateTarget(target, bindings, file, line);
        }
    }

    private bool StableArity(IReadOnlyList<string> tokens, List<int> listExpansions, Dictionary<string, string> bindings, int through)
    {
        if (listExpansions == null)
        {
            return true;
        }

        foreach (var index in listExpansions)
        {
            if (index > through)
            {
                break;
            }

            var value = Expand(tokens[index], bindings);
            if (string.IsNullOrEmpty(value) || value.Contains(';'))
            {
                return false;
            }
        }

        return true;
    }

    private void InvalidateTarget(string target, Dictionary<string, string> bindings, string file, int line)
    {
        var key = Expand(target, bindings);
        if (key == null || key.Contains(';'))
        {
            InvalidateFacts();
            ClearBindings(bindings);
            return;
        }

        Set(key, null, null, false, file, line, "unsupported-write");
        if (bindings?.ContainsKey(key) == true)
        {
            bindings[key] = null;
        }
    }

    private bool VersionAliasesUnchanged(Dictionary<string, string> bindings)
    {
        if (unresolvedDeclaration || candidates.Count == 0 || names.Count != 1)
        {
            return false;
        }

        var version = candidates[^1].Value;
        return AliasUnchanged("PROJECT_VERSION", version, bindings) && AliasUnchanged(versionAlias, version, bindings);
    }

    private bool AliasUnchanged(string alias, string version, Dictionary<string, string> bindings) => Value(alias) == version && !(bindings != null && bindings.TryGetValue(alias, out var value) && value != version);

    private bool IsVersionAlias(string key) => key == "PROJECT_VERSION" || (versionAlias != null && key == versionAlias);

    private void InvalidateFacts()
    {
        unresolvedDeclaration |= candidates.Count > 0;
        foreach (var key in variables.Keys.Where(key => !key.StartsWith("CMAKE_CURRENT_", StringComparison.Ordinal)).ToArray())
        {
            variables[key] = new Fact(null, null);
        }
    }

    private void ForgetFacts()
    {
        // Losing pre-loop values is not itself a write. Possible body writes
        // still invalidate aliases/candidates through the common effect path.
        foreach (var key in variables.Keys.Where(key => !key.StartsWith("CMAKE_CURRENT_", StringComparison.Ordinal) && !(candidates.Count > 0 && IsVersionAlias(key))).ToArray())
        {
            variables[key] = new Fact(null, null);
        }
    }

    private string Value(string name) => variables.TryGetValue(name, out var fact) && fact.Defined == true ? fact.Value : null;

    private string Expand(string text, IReadOnlyDictionary<string, string> bindings = null)
    {
        if (text == null)
        {
            return null;
        }

        var unresolved = false;
        var value = Variable.Replace(text, match =>
        {
            var name = match.Groups[1].Value;
            var replacement = bindings != null && bindings.TryGetValue(name, out var bound) ? bound : Value(name);
            unresolved |= replacement == null;
            return replacement ?? match.Value;
        });
        return unresolved || value.Contains('$') ? null : value;
    }

    private static bool? Boolean(string value)
    {
        if (value.Equals("TRUE", StringComparison.OrdinalIgnoreCase) || value.Equals("ON", StringComparison.OrdinalIgnoreCase) || value.Equals("YES", StringComparison.OrdinalIgnoreCase) || value.Equals("Y", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (string.IsNullOrEmpty(value) || value.Equals("FALSE", StringComparison.OrdinalIgnoreCase) || value.Equals("OFF", StringComparison.OrdinalIgnoreCase) || value.Equals("NO", StringComparison.OrdinalIgnoreCase) || value.Equals("N", StringComparison.OrdinalIgnoreCase) || value.Equals("IGNORE", StringComparison.OrdinalIgnoreCase) || value.Equals("NOTFOUND", StringComparison.OrdinalIgnoreCase) || value.EndsWith("-NOTFOUND", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (double.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out var number) && double.IsFinite(number))
        {
            return number != 0;
        }

        return null;
    }

    private static bool? And(bool? first, bool? second) => first == false || second == false ? false : first == true && second == true ? true : null;

    private static bool? Not(bool? value) => value.HasValue ? !value.Value : null;

    private readonly record struct Fact(bool? Defined, string Value);

    private readonly record struct Conditional(bool? Parent, bool? Remaining);

    private sealed record Definition(IReadOnlyList<string> Parameters, IReadOnlyList<Command> Body);
}
