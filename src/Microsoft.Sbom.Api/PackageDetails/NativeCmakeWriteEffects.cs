// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

namespace Microsoft.Sbom.Api.PackageDetails;

/// <summary>
/// Literal output-variable positions, not value evaluation. Unknown forms must
/// invalidate facts; filesystem-only commands do not mutate version variables.
/// See the CMake string, list, file, and execute_process command references.
/// </summary>
internal static class NativeCmakeWriteEffects
{
    private static readonly Dictionary<string, int> StringOutputs = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
    {
        ["APPEND"] = 1, ["PREPEND"] = 1, ["CONCAT"] = 1, ["JOIN"] = 2,
        ["REPLACE"] = 3, ["FIND"] = 3, ["LENGTH"] = 2, ["SUBSTRING"] = 4,
        ["TOLOWER"] = 2, ["TOUPPER"] = 2, ["STRIP"] = 2, ["GENEX_STRIP"] = 2,
        ["CONFIGURE"] = 2, ["REPEAT"] = 3, ["MAKE_C_IDENTIFIER"] = 2,
        ["ASCII"] = -1, ["HEX"] = 2, ["RANDOM"] = -1, ["TIMESTAMP"] = 1,
        ["UUID"] = 1, ["COMPARE"] = 4, ["MD5"] = 1, ["SHA1"] = 1,
        ["SHA224"] = 1, ["SHA256"] = 1, ["SHA384"] = 1, ["SHA512"] = 1,
    };

    private static readonly Dictionary<string, int> ListOutputs = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
    {
        ["LENGTH"] = 2, ["GET"] = -1, ["JOIN"] = 3, ["SUBLIST"] = 4, ["FIND"] = 3,
        ["APPEND"] = 1, ["PREPEND"] = 1, ["INSERT"] = 1, ["FILTER"] = 1,
        ["REMOVE_ITEM"] = 1, ["REMOVE_AT"] = 1, ["REMOVE_DUPLICATES"] = 1,
        ["REVERSE"] = 1, ["SORT"] = 1,
    };

    private static readonly Dictionary<string, int> FileOutputs = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
    {
        ["READ"] = 2, ["STRINGS"] = 2, ["GLOB"] = 1, ["GLOB_RECURSE"] = 1,
        ["SIZE"] = 2, ["READ_SYMLINK"] = 2, ["TO_CMAKE_PATH"] = 2,
        ["TO_NATIVE_PATH"] = 2, ["RELATIVE_PATH"] = 1,
    };

    private static readonly HashSet<string> FilesystemOnly = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "WRITE", "APPEND", "MAKE_DIRECTORY", "REMOVE", "REMOVE_RECURSE", "RENAME",
        "COPY", "COPY_FILE", "INSTALL", "CREATE_LINK", "TOUCH", "TOUCH_NOCREATE",
        "CHMOD", "CHMOD_RECURSE", "GENERATE", "CONFIGURE", "LOCK", "DOWNLOAD", "UPLOAD",
    };

    internal static bool IsOptionOutput(string command, string token) => command switch
    {
        "execute_process" => token is "OUTPUT_VARIABLE" or "ERROR_VARIABLE" or "RESULT_VARIABLE" or "RESULTS_VARIABLE",
        "file" => token is "RESULT" or "RESULT_VARIABLE" or "STATUS" or "LOG",
        _ => false,
    };

    internal static bool TryTarget(string command, IReadOnlyList<string> tokens, out string target, out int targetPosition)
    {
        target = null;
        targetPosition = -1;
        var index = -2;
        if (command is "set" or "unset" or "option" or "get_property" or "get_cmake_property" or "get_directory_property" or "get_target_property" or "get_source_file_property" or "get_filename_component" or "separate_arguments")
        {
            index = 0;
        }
        else if (command == "get_test_property")
        {
            index = 2;
        }
        else if (command == "math")
        {
            index = 1;
        }
        else if (command == "string")
        {
            if (tokens[0].Equals("REGEX", StringComparison.OrdinalIgnoreCase) && tokens.Count > 1)
            {
                index = tokens[1].Equals("REPLACE", StringComparison.OrdinalIgnoreCase) ? 4 : tokens[1].Equals("MATCH", StringComparison.OrdinalIgnoreCase) || tokens[1].Equals("MATCHALL", StringComparison.OrdinalIgnoreCase) ? 3 : -2;
            }
            else if (!StringOutputs.TryGetValue(tokens[0], out index))
            {
                return false;
            }
        }
        else if (command == "list")
        {
            if (!ListOutputs.TryGetValue(tokens[0], out index))
            {
                return false;
            }
        }
        else if (command == "file")
        {
            if (FilesystemOnly.Contains(tokens[0]))
            {
                return true;
            }

            if (!FileOutputs.TryGetValue(tokens[0], out index))
            {
                return false;
            }
        }
        else if (command is "include" or "cmake_language" or "cmake_path")
        {
            return false;
        }
        else
        {
            return true;
        }

        index = index == -1 ? tokens.Count - 1 : index;
        if (index < 0 || index >= tokens.Count)
        {
            return false;
        }

        target = tokens[index];
        targetPosition = index;
        return true;
    }
}
