// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using Microsoft.Sbom.Contracts;

namespace Microsoft.Sbom.Api.PackageDetails;

/// <summary>
/// Supplies native project declarations from a source tree without executing source code.
/// </summary>
public interface INativeBuildPackageDetector
{
    /// <summary>
    /// Reads unambiguous source-declared native packages and their provenance.
    /// </summary>
    /// <param name="sourceRoot">Root of the source tree.</param>
    /// <returns>Packages with source-location-sensitive identities.</returns>
    IReadOnlyList<SbomPackage> Detect(string sourceRoot);
}
