// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.IO;
using System.Linq;
using Microsoft.Sbom.Api.PackageDetails;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Sbom.Api.Tests.PackageDetails;

[TestClass]
public class NativeBuildPackageDetectorTests
{
    private static readonly NativeBuildPackageDetector Detector = new NativeBuildPackageDetector();

    [TestMethod]
    public void ResolvesProjectAndRocmSetupVersionWithProvenance()
    {
        WithSource(root =>
        {
            File.WriteAllText(Path.Join(root, "CMakeLists.txt"), "project(Example LANGUAGES CXX)\nset(VERSION_STRING \"5.9.0\")\nrocm_setup_version(VERSION ${VERSION_STRING})\n");
            var package = Detector.Detect(root).Single();
            Assert.AreEqual("Example", package.PackageName);
            Assert.AreEqual("5.9.0", package.PackageVersion);
            StringAssert.Contains(package.PackageUrl, "source_file=CMakeLists.txt");
            StringAssert.Contains(package.PackageUrl, "source_line=3");
            StringAssert.Contains(package.PackageUrl, "version_key=rocm_setup_version");
        });
    }

    [TestMethod]
    public void ReadsExactLocalVersionFileThroughInclude()
    {
        WithSource(root =>
        {
            Directory.CreateDirectory(Path.Join(root, "cmake"));
            File.WriteAllText(Path.Join(root, "VERSION"), "2.4.6\n");
            File.WriteAllText(Path.Join(root, "cmake", "version.cmake"), "file(READ \"${CMAKE_CURRENT_LIST_DIR}/../VERSION\" RELEASE)\nstring(STRIP \"${RELEASE}\" RELEASE)\n");
            File.WriteAllText(Path.Join(root, "CMakeLists.txt"), "include(cmake/version.cmake)\nproject(Example VERSION ${RELEASE} LANGUAGES C)\n");
            Assert.AreEqual("2.4.6", Detector.Detect(root).Single().PackageVersion);
        });
    }

    [TestMethod]
    public void DoesNotInventVersionsFromMinimumDependenciesOrMacroDefinitions()
    {
        WithSource(root =>
        {
            File.WriteAllText(Path.Join(root, "CMakeLists.txt"), "macro(example)\nproject(Fake VERSION 99.0)\nendmacro()\nproject(Real)\nfind_package(Dependency 8.9 REQUIRED)\n");
            Assert.AreEqual(0, Detector.Detect(root).Count);
        });
    }

    [TestMethod]
    public void RefusesConflictingConditionalVersionAssignments()
    {
        WithSource(root =>
        {
            File.WriteAllText(Path.Join(root, "CMakeLists.txt"), "project(Example)\nif(UNKNOWN_OPTION)\nset(VERSION_STRING 1.2.3)\nelse()\nset(VERSION_STRING 4.5.6)\nendif()\nrocm_setup_version(VERSION ${VERSION_STRING})\n");
            Assert.AreEqual(0, Detector.Detect(root).Count);
        });
    }

    [TestMethod]
    public void KeepsSameNameProjectsAtDifferentSourceLocationsDistinct()
    {
        WithSource(root =>
        {
            foreach (var version in new[] { "1.2.3", "4.5.6" })
            {
                var directory = Directory.CreateDirectory(Path.Join(root, version));
                File.WriteAllText(Path.Join(directory.FullName, "CMakeLists.txt"), $"project(Example VERSION {version})\n");
            }

            var packages = Detector.Detect(root);
            Assert.AreEqual(2, packages.Count);
            Assert.AreEqual(2, packages.Select(package => package.Id).Distinct().Count());
            Assert.AreEqual(2, packages.Select(package => package.PackageUrl).Distinct().Count());
        });
    }

    [TestMethod]
    public void DetectsMesonLiteralVariableAndVersionFile()
    {
        WithSource(root =>
        {
            File.WriteAllText(Path.Join(root, "VERSION"), "3.6.3\n");
            File.WriteAllText(Path.Join(root, "meson.build"), "release = '3.6.3'\nproject('Example', 'cpp', version : release)\n");
            Assert.AreEqual("3.6.3", Detector.Detect(root).Single().PackageVersion);
            File.WriteAllText(Path.Join(root, "meson.build"), "project('Example', 'cpp', version : files('VERSION'))\n");
            Assert.AreEqual("3.6.3", Detector.Detect(root).Single().PackageVersion);
        });
    }

    [TestMethod]
    public void DoesNotExecuteBuildCommandsOrUseUnresolvedVersions()
    {
        WithSource(root =>
        {
            File.WriteAllText(Path.Join(root, "CMakeLists.txt"), "execute_process(COMMAND touch SHOULD_NOT_EXIST)\nproject(Example VERSION ${UNKNOWN})\n");
            Assert.AreEqual(0, Detector.Detect(root).Count);
            Assert.IsFalse(File.Exists(Path.Join(root, "SHOULD_NOT_EXIST")));
        });
    }

    [TestMethod]
    public void PreservesDistinctLiteralVersionsAndSkipsAmbiguousProjectIdentity()
    {
        WithSource(root =>
        {
            File.WriteAllText(Path.Join(root, "CMakeLists.txt"), "if(UNKNOWN)\nproject(One VERSION 1.2.3)\nelse()\nproject(Two VERSION 4.5.6)\nendif()\n");
            Assert.AreEqual(0, Detector.Detect(root).Count);
        });
    }

    [TestMethod]
    public void IgnoresBracketCommentsAndRetainsRepositoryProvenance()
    {
        WithSource(root =>
        {
            Directory.CreateDirectory(Path.Join(root, ".git"));
            File.WriteAllText(Path.Join(root, ".git", "HEAD"), "0123456789abcdef0123456789abcdef01234567\n");
            File.WriteAllText(Path.Join(root, ".git", "config"), "[remote \"origin\"]\nurl = https://example.org/native.git\n");
            File.WriteAllText(Path.Join(root, "CMakeLists.txt"), "#[=[\nproject(Fake VERSION 99.0)\n]=]\nproject(Real VERSION 3.4.5)\n");
            var package = Detector.Detect(root).Single();
            Assert.AreEqual("Real", package.PackageName);
            Assert.AreEqual("git+https://example.org/native.git@0123456789abcdef0123456789abcdef01234567", package.PackageSource);
            StringAssert.Contains(package.PackageUrl, "source_line=4");
            StringAssert.Contains(package.PackageUrl, "vcs_url=");
        });
    }

    [TestMethod]
    public void ReadsExplicitCurrentProjectVersionAndRegexCapturedVersionFile()
    {
        WithSource(root =>
        {
            File.WriteAllText(Path.Join(root, "CMakeLists.txt"), "project(Example)\nset(RELEASE \"1.5.0\" CACHE STRING \"Release\")\nset(PROJECT_VERSION \"${RELEASE}\")\n");
            Assert.AreEqual("1.5.0", Detector.Detect(root).Single().PackageVersion);
            File.WriteAllText(Path.Join(root, "release.mk"), "MAJOR := 2\nMINOR := 32\nPATCH := 3\n");
            File.WriteAllText(Path.Join(root, "CMakeLists.txt"), "file(READ release.mk release)\nif(\"${release}\" MATCHES \"MAJOR *:= *([0-9]*)\")\nset(V_MAJOR ${CMAKE_MATCH_1})\nendif()\nif(\"${release}\" MATCHES \"MINOR *:= *([0-9]*)\")\nset(V_MINOR ${CMAKE_MATCH_1})\nendif()\nif(\"${release}\" MATCHES \"PATCH *:= *([0-9]*)\")\nset(V_PATCH ${CMAKE_MATCH_1})\nendif()\nproject(Example)\nrocm_setup_version(VERSION ${V_MAJOR}.${V_MINOR}.${V_PATCH})\n");
            Assert.AreEqual("2.32.3", Detector.Detect(root).Single().PackageVersion);
        });
    }

    [TestMethod]
    public void ResolvesBoundedRegexReplacementFromExactVersionFile()
    {
        WithSource(root =>
        {
            File.WriteAllText(Path.Join(root, "VERSION"), "7.8.9-development\n");
            File.WriteAllText(Path.Join(root, "CMakeLists.txt"), "file(READ VERSION FULL_VERSION)\nstring(REGEX REPLACE \"([0-9]+)\\\\.([0-9]+)\\\\.([0-9]+)(.*)\" \"\\\\1.\\\\2.\\\\3\" RELEASE \"${FULL_VERSION}\")\nproject(Example VERSION ${RELEASE})\n");
            Assert.AreEqual("7.8.9", Detector.Detect(root).Single().PackageVersion);
        });
    }

    [TestMethod]
    public void DoesNotFallBackToEarlierVersionWhenLaterDeclarationIsUnknown()
    {
        WithSource(root =>
        {
            File.WriteAllText(Path.Join(root, "CMakeLists.txt"), "project(Example VERSION 1.2.3)\nrocm_setup_version(VERSION ${UNKNOWN})\n");
            Assert.AreEqual(0, Detector.Detect(root).Count);
        });
    }

    [TestMethod]
    [DataRow("FALSE")]
    [DataRow("UNESTABLISHED_OPTION")]
    public void DoesNotEstablishVersionsFromUnestablishedBranches(string condition)
    {
        WithSource(root =>
        {
            File.WriteAllText(Path.Join(root, "CMakeLists.txt"), $"project(Example)\nif({condition})\nset(PROJECT_VERSION 9.9.9)\nendif()\n");
            Assert.AreEqual(0, Detector.Detect(root).Count);
        });
    }

    [TestMethod]
    public void PreservesDistinctOwningProjectsWithSharedVersionDeclaration()
    {
        WithSource(root =>
        {
            Directory.CreateDirectory(Path.Join(root, "shared"));
            File.WriteAllText(Path.Join(root, "shared", "version.cmake"), "rocm_setup_version(VERSION 1.2.3)\n");
            foreach (var name in new[] { "a", "b" })
            {
                var directory = Directory.CreateDirectory(Path.Join(root, name));
                File.WriteAllText(Path.Join(directory.FullName, "CMakeLists.txt"), "project(Example)\ninclude(../shared/version.cmake)\n");
            }

            var packages = Detector.Detect(root);
            Assert.AreEqual(2, packages.Count);
            Assert.AreEqual(2, packages.Select(package => package.Id).Distinct().Count());
            Assert.AreEqual(2, packages.Select(package => package.PackageUrl).Distinct().Count());
            Assert.IsTrue(packages.All(package => package.PackageUrl.Contains("source_file=shared%2Fversion.cmake")));
            Assert.IsTrue(packages.All(package => package.PackageUrl.Contains("source_project=")));
        });
    }

    [TestMethod]
    [DataRow("'1.2.3' + '-dev'")]
    [DataRow("release + '-dev'")]
    [DataRow("'1.2.3'.replace('3', '4')")]
    public void RejectsUnsupportedWholeMesonVersionExpressions(string expression)
    {
        WithSource(root =>
        {
            File.WriteAllText(Path.Join(root, "meson.build"), $"release = '1.2.3'\nproject('Example', 'c', version: {expression})\n");
            Assert.AreEqual(0, Detector.Detect(root).Count);
        });
    }

    [TestMethod]
    public void ResolvesLiteralModulePathInsteadOfNearbyNamesake()
    {
        WithSource(root =>
        {
            Directory.CreateDirectory(Path.Join(root, "cmake"));
            File.WriteAllText(Path.Join(root, "Release.cmake"), "set(RELEASE 9.9.9)\n");
            File.WriteAllText(Path.Join(root, "cmake", "Release.cmake"), "set(RELEASE 2.3.4)\n");
            File.WriteAllText(Path.Join(root, "CMakeLists.txt"), "set(CMAKE_MODULE_PATH \"${CMAKE_CURRENT_SOURCE_DIR}/cmake\")\ninclude(Release)\nproject(Example VERSION ${RELEASE})\n");
            Assert.AreEqual("2.3.4", Detector.Detect(root).Single().PackageVersion);
        });
    }

    [TestMethod]
    public void ReadsRelativeVersionFromSourceDirectoryNotIncludedListDirectory()
    {
        WithSource(root =>
        {
            Directory.CreateDirectory(Path.Join(root, "cmake"));
            File.WriteAllText(Path.Join(root, "VERSION"), "1.2.3\n");
            File.WriteAllText(Path.Join(root, "cmake", "VERSION"), "9.9.9\n");
            File.WriteAllText(Path.Join(root, "cmake", "release.cmake"), "file(READ VERSION RELEASE)\n");
            File.WriteAllText(Path.Join(root, "CMakeLists.txt"), "include(cmake/release.cmake)\nproject(Example VERSION ${RELEASE})\n");
            Assert.AreEqual("1.2.3", Detector.Detect(root).Single().PackageVersion);
        });
    }

    [TestMethod]
    [DataRow("function", "endfunction", "PARENT_SCOPE")]
    [DataRow("macro", "endmacro", "")]
    public void InvalidatesFactsAffectedByCalledUserDefinedWrites(string kind, string end, string scope)
    {
        WithSource(root =>
        {
            var source = "set(RELEASE 1.2.3)\n$KIND(update_release target)\nset(${target} 2.3.4 $SCOPE)\n$END()\nupdate_release(RELEASE)\nproject(Example VERSION ${RELEASE})\n";
            File.WriteAllText(Path.Join(root, "CMakeLists.txt"), source.Replace("$KIND", kind).Replace("$END", end).Replace("$SCOPE", scope));
            Assert.AreEqual(0, Detector.Detect(root).Count);
        });
    }

    [TestMethod]
    [DataRow("unset(RELEASE)")]
    [DataRow("set(RELEASE)")]
    [DataRow("set(RELEASE \"\")")]
    public void ClearsUnsetAndEmptyVersionFacts(string mutation)
    {
        WithSource(root =>
        {
            File.WriteAllText(Path.Join(root, "CMakeLists.txt"), "set(RELEASE 1.2.3)\n" + mutation + "\nproject(Example VERSION ${RELEASE})\n");
            Assert.AreEqual(0, Detector.Detect(root).Count);
        });
    }

    [TestMethod]
    public void TreatsBracketArgumentContentsAsOpaqueData()
    {
        WithSource(root =>
        {
            File.WriteAllText(Path.Join(root, "CMakeLists.txt"), "message([=[)\nproject(Example VERSION 9.9.9)\n]=])\nproject(Example)\n");
            Assert.AreEqual(0, Detector.Detect(root).Count);
        });
    }

    [TestMethod]
    public void PreservesEstablishedBranchesAndFreshUnconditionalAssignments()
    {
        WithSource(root =>
        {
            File.WriteAllText(Path.Join(root, "CMakeLists.txt"), "if(TRUE)\nset(RELEASE 1.2.3)\nelse()\nset(RELEASE 9.9.9)\nendif()\nproject(Example VERSION ${RELEASE})\n");
            Assert.AreEqual("1.2.3", Detector.Detect(root).Single().PackageVersion);
            File.WriteAllText(Path.Join(root, "CMakeLists.txt"), "set(RELEASE 1.2.3)\nif(UNESTABLISHED_OPTION)\nset(RELEASE 9.9.9)\nendif()\nproject(Example VERSION ${RELEASE})\n");
            Assert.AreEqual(0, Detector.Detect(root).Count);
            File.WriteAllText(Path.Join(root, "CMakeLists.txt"), "set(RELEASE 1.2.3)\nunset(RELEASE)\nset(RELEASE 2.3.4)\nproject(Example VERSION ${RELEASE})\n");
            Assert.AreEqual("2.3.4", Detector.Detect(root).Single().PackageVersion);
        });
    }

    [TestMethod]
    public void SkipsFalseWhileAndDeclinesUnestablishedLoopWrites()
    {
        WithSource(root =>
        {
            File.WriteAllText(Path.Join(root, "CMakeLists.txt"), "set(RELEASE 1.2.3)\nwhile(FALSE)\nset(RELEASE 9.9.9)\nendwhile()\nproject(Example VERSION ${RELEASE})\n");
            Assert.AreEqual("1.2.3", Detector.Detect(root).Single().PackageVersion);
            File.WriteAllText(Path.Join(root, "CMakeLists.txt"), "foreach(item IN ITEMS)\nset(RELEASE 9.9.9)\nendforeach()\nproject(Example VERSION ${RELEASE})\n");
            Assert.AreEqual(0, Detector.Detect(root).Count);
            File.WriteAllText(Path.Join(root, "CMakeLists.txt"), "set(RELEASE 1.2.3)\nwhile(UNESTABLISHED_OPTION)\nset(RELEASE 9.9.9)\nendwhile()\nproject(Example VERSION ${RELEASE})\n");
            Assert.AreEqual(0, Detector.Detect(root).Count);
            File.WriteAllText(Path.Join(root, "CMakeLists.txt"), "set(key UNUSED)\nset(RELEASE 1.2.3)\nforeach(key IN ITEMS RELEASE)\nset(${key} 9.9.9)\nendforeach()\nproject(Example VERSION ${RELEASE})\n");
            Assert.AreEqual(0, Detector.Detect(root).Count);
            File.WriteAllText(Path.Join(root, "CMakeLists.txt"), "set(RELEASE 1.2.3)\nwhile(UNESTABLISHED_OPTION)\nset(RELEASE 9.9.9)\nendwhile()\nset(RELEASE 2.3.4)\nproject(Example VERSION ${RELEASE})\n");
            Assert.AreEqual("2.3.4", Detector.Detect(root).Single().PackageVersion);
        });
    }

    [TestMethod]
    public void ConditionalUnrelatedHelperPreservesEstablishedProjectRelease()
    {
        WithSource(root =>
        {
            File.WriteAllText(Path.Join(root, "CMakeLists.txt"), "project(Example VERSION 3.6.3 LANGUAGES NONE)\nif(UNESTABLISHED_OPTION)\nfunction(adjust target)\nset(${target} data PARENT_SCOPE)\nendfunction()\nadjust(UNRELATED)\nendif()\n");
            Assert.AreEqual("3.6.3", Detector.Detect(root).Single().PackageVersion);
        });
    }

    [TestMethod]
    public void ConditionalFunctionReplacementRetainsAllPossibleWriteEffects()
    {
        WithSource(root =>
        {
            File.WriteAllText(Path.Join(root, "CMakeLists.txt"), "set(RELEASE 1.2.3)\nfunction(adjust)\nset(RELEASE 9.9.9 PARENT_SCOPE)\nendfunction()\nif(UNESTABLISHED_OPTION)\nfunction(adjust)\nset(UNRELATED data PARENT_SCOPE)\nendfunction()\nendif()\nadjust()\nproject(Example VERSION ${RELEASE} LANGUAGES NONE)\n");
            Assert.AreEqual(0, Detector.Detect(root).Count);
        });
    }

    [TestMethod]
    [DataRow("set(target UNUSED)\nmacro(inner)\nset(${target} 9.9.9 PARENT_SCOPE)\nendmacro()\nfunction(outer target)\ninner()\nendfunction()\nouter(RELEASE)")]
    [DataRow("function(adjust target)\nset(target RELEASE)\nset(${target} 9.9.9 PARENT_SCOPE)\nendfunction()\nadjust(UNRELATED)")]
    [DataRow("macro(adjust target)\nif(\"${target}\" STREQUAL \"UNRELATED\")\nadjust(RELEASE)\nendif()\nset(${target} 9.9.9)\nendmacro()\nadjust(UNRELATED)")]
    [DataRow("function(adjust target)\nset(${target} 9.9.9 PARENT_SCOPE)\nendfunction()\ncmake_language(CALL adjust RELEASE)")]
    public void RejectsUnestablishedCallgraphWriteTargets(string calls)
    {
        WithSource(root =>
        {
            File.WriteAllText(Path.Join(root, "CMakeLists.txt"), "set(RELEASE 1.2.3)\n" + calls + "\nproject(Example VERSION ${RELEASE} LANGUAGES NONE)\n");
            Assert.AreEqual(0, Detector.Detect(root).Count);
        });
    }

    [TestMethod]
    public void FalseConditionalDefinitionCannotReplaceAnEstablishedHelper()
    {
        WithSource(root =>
        {
            File.WriteAllText(Path.Join(root, "CMakeLists.txt"), "project(Example VERSION 3.6.3 LANGUAGES NONE)\nfunction(adjust)\nset(UNRELATED data PARENT_SCOPE)\nendfunction()\nif(FALSE)\nfunction(adjust)\nset(PROJECT_VERSION 9.9.9 PARENT_SCOPE)\nendfunction()\nendif()\nadjust()\n");
            Assert.AreEqual("3.6.3", Detector.Detect(root).Single().PackageVersion);
        });
    }

    [TestMethod]
    public void RecursiveUnknownWritesInvalidateAnEarlierLiteralProjectRelease()
    {
        WithSource(root =>
        {
            File.WriteAllText(Path.Join(root, "CMakeLists.txt"), "cmake_minimum_required(VERSION 3.20)\nproject(Example VERSION 1.2.3 LANGUAGES NONE)\nmacro(adjust target)\nif(\"${target}\" STREQUAL \"UNRELATED\")\nadjust(PROJECT_VERSION)\nendif()\nset(${target} 9.9.9)\nendmacro()\nadjust(UNRELATED)\n");
            Assert.AreEqual(0, Detector.Detect(root).Count);
        });
    }

    [TestMethod]
    [DataRow("function(export target)\nset(PROJECT_VERSION 9.9.9)\nset(${target} ${${target}} PARENT_SCOPE)\nendfunction()\nexport(PROJECT_VERSION)", false)]
    [DataRow("function(export target PROJECT_VERSION)\nset(${target} ${${target}} PARENT_SCOPE)\nendfunction()\nexport(PROJECT_VERSION 9.9.9)", false)]
    [DataRow("function(export target)\nif(UNESTABLISHED_OPTION)\nset(PROJECT_VERSION 9.9.9)\nendif()\nset(${target} ${${target}} PARENT_SCOPE)\nendfunction()\nexport(PROJECT_VERSION)", false)]
    [DataRow("function(export target)\nset(${target} ${${target}} PARENT_SCOPE)\nendfunction()\nexport(PROJECT_VERSION)", true)]
    [DataRow("function(export target)\nset(${target} ${${target}} 9.9.9 PARENT_SCOPE)\nendfunction()\nexport(PROJECT_VERSION)", false)]
    [DataRow("function(export target)\nset(${target} ${${target}} PARENT_SCOPE)\nendfunction()\nexport(\"PROJECT_VERSION;9.9.9\")", false)]
    [DataRow("function(_export_old)\nset(PROJECT_VERSION 9.9.9 PARENT_SCOPE)\nendfunction()\nfunction(_export_other)\nset(UNRELATED data PARENT_SCOPE)\nendfunction()\ncmake_language(CALL _export_${UNESTABLISHED_OPTION})", false)]
    [DataRow("string(REPLACE 1 9 PROJECT_VERSION \"${PROJECT_VERSION}\")", false)]
    [DataRow("string(REPLACE _ - UNRELATED abc)\nlist(APPEND UNRELATED def)\nfile(WRITE \"${CMAKE_CURRENT_BINARY_DIR}/generated\" text)", true)]
    [DataRow("set(args \"1;9\")\nstring(REPLACE ${args} PROJECT_VERSION \"${PROJECT_VERSION}\")", false)]
    [DataRow("macro(mutate args)\nstring(REPLACE ${args} PROJECT_VERSION \"${PROJECT_VERSION}\")\nendmacro()\nmutate(\"1;9\")", false)]
    [DataRow("set(args \"1;9\")\nstring(REPLACE \"${args}\" x UNRELATED \"${PROJECT_VERSION}\")", true)]
    [DataRow("set(args 1)\nstring(REPLACE ${args} 9 UNRELATED \"${PROJECT_VERSION}\")", true)]
    public void PreservesMetadataOnlyAcrossProvenUnrelatedOrIdentityWrites(string statements, bool preserved)
    {
        WithSource(root =>
        {
            File.WriteAllText(Path.Join(root, "CMakeLists.txt"), "cmake_minimum_required(VERSION 3.20)\nproject(Example VERSION 1.2.3 LANGUAGES NONE)\n" + statements + "\n");
            var packages = Detector.Detect(root);
            Assert.AreEqual(preserved ? 1 : 0, packages.Count);
            if (preserved)
            {
                Assert.AreEqual("1.2.3", packages.Single().PackageVersion);
            }
        });
    }

    private static void WithSource(Action<string> action)
    {
        var root = Path.Join(Path.GetTempPath(), $"sbom-native-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        try
        {
            action(root);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }
}
