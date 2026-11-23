// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Entities;
using Microsoft.Sbom.Api.Manifest.FileHashes;
using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Contracts.Enums;
using Microsoft.Sbom.Entities;
using Microsoft.Sbom.Extensions.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using ErrorType = Microsoft.Sbom.Api.Entities.ErrorType;

namespace Microsoft.Sbom.Api.Executors.Tests;

[TestClass]
public class HashValidatorTests
{
    [TestMethod]
    public async Task HashValidatorTest_ValidHash_SucceedsAsync()
    {
        var fileList = new HashSet<string>()
        {
            "TEST1",
            "TEST2",
            "TEST3"
        };
        var hashDict = new Dictionary<string, Checksum[]>(StringComparer.InvariantCultureIgnoreCase);
        foreach (var file in fileList)
        {
            hashDict[file.ToLower()] = new Checksum[] { new Checksum { Algorithm = AlgorithmName.SHA256, ChecksumValue = $"{file}_hash" } };
        }

        var configuration = new Mock<IConfiguration>();
        configuration.SetupGet(c => c.HashAlgorithm).Returns(new ConfigurationSetting<AlgorithmName> { Value = Constants.DefaultHashAlgorithmName });

        var files = Channel.CreateUnbounded<InternalSbomFileInfo>();
        foreach (var file in fileList)
        {
            await files.Writer.WriteAsync(new InternalSbomFileInfo { Path = file.ToUpper(), Checksum = new Checksum[] { new Checksum { Algorithm = Constants.DefaultHashAlgorithmName, ChecksumValue = $"{file}_hash" } } });
        }

        files.Writer.Complete();

        var validator = new HashValidator(configuration.Object, new ManifestData { HashesMap = hashDict });
        var validationResults = validator.Validate(files);

        await foreach (var output in validationResults.output.ReadAllAsync())
        {
            Assert.IsTrue(fileList.Remove(output.Path));
        }

        Assert.AreEqual(0, fileList.Count);
        Assert.AreEqual(0, validationResults.errors.Count);
    }

    [TestMethod]
    public async Task HashValidatorTest_InValidHash_ReturnsValidationErrorAsync()
    {
        var fileList = new HashSet<string>()
        {
            "TEST1",
            "TEST2",
            "TEST3"
        };

        var hashDict = new Dictionary<string, Checksum[]>(StringComparer.InvariantCultureIgnoreCase);
        foreach (var file in fileList)
        {
            hashDict[file.ToLower()] = new Checksum[] { new Checksum { Algorithm = AlgorithmName.SHA256, ChecksumValue = $"{file}_hashInvalid" } };
        }

        var configuration = new Mock<IConfiguration>();
        configuration.SetupGet(c => c.HashAlgorithm).Returns(new ConfigurationSetting<AlgorithmName> { Value = Constants.DefaultHashAlgorithmName });

        var files = Channel.CreateUnbounded<InternalSbomFileInfo>();
        foreach (var file in fileList)
        {
            await files.Writer.WriteAsync(new InternalSbomFileInfo { Path = file.ToUpper(), Checksum = new Checksum[] { new Checksum { Algorithm = Constants.DefaultHashAlgorithmName, ChecksumValue = $"{file}_hash" } } });
        }

        files.Writer.Complete();

        var validator = new HashValidator(configuration.Object, new ManifestData { HashesMap = hashDict });
        var validationResults = validator.Validate(files);

        await foreach (var output in validationResults.output.ReadAllAsync())
        {
            Assert.IsTrue(fileList.Remove(output.Path));
        }

        await foreach (var error in validationResults.errors.ReadAllAsync())
        {
            Assert.AreEqual(ErrorType.InvalidHash, error.ErrorType);
            Assert.IsTrue(fileList.Remove(error.Path));
        }

        Assert.AreEqual(0, fileList.Count);
    }

    [TestMethod]
    public async Task HashValidatorTest_AdditionalFile_ReturnsAdditionalFileFailureAsync()
    {
        var fileList = new HashSet<string>()
        {
            "TEST1",
            "TEST2",
            "TEST3"
        };

        var hashDict = new Dictionary<string, Checksum[]>(StringComparer.InvariantCultureIgnoreCase);
        foreach (var file in fileList)
        {
            hashDict[file.ToLower()] = new Checksum[] { new Checksum { Algorithm = AlgorithmName.SHA256, ChecksumValue = $"{file}_hash" } };
        }

        var configuration = new Mock<IConfiguration>();
        configuration.SetupGet(c => c.HashAlgorithm).Returns(new ConfigurationSetting<AlgorithmName> { Value = Constants.DefaultHashAlgorithmName });

        var files = Channel.CreateUnbounded<InternalSbomFileInfo>();
        var errors = Channel.CreateUnbounded<FileValidationResult>();

        foreach (var file in fileList)
        {
            await files.Writer.WriteAsync(new InternalSbomFileInfo { Path = file.ToUpper(), Checksum = new Checksum[] { new Checksum { Algorithm = Constants.DefaultHashAlgorithmName, ChecksumValue = $"{file}_hash" } } });
        }

        // Additional file.
        await files.Writer.WriteAsync(new InternalSbomFileInfo { Path = "TEST4", Checksum = new Checksum[] { new Checksum { Algorithm = Constants.DefaultHashAlgorithmName, ChecksumValue = "TEST4_hash" } } });

        files.Writer.Complete();
        errors.Writer.Complete();

        var validator = new HashValidator(configuration.Object, new ManifestData { HashesMap = hashDict });
        var validationResults = validator.Validate(files);

        await foreach (var error in validationResults.errors.ReadAllAsync())
        {
            Assert.AreEqual(ErrorType.AdditionalFile, error.ErrorType);
            Assert.AreEqual("TEST4", error.Path);
        }

        await foreach (var output in validationResults.output.ReadAllAsync())
        {
            Assert.IsTrue(fileList.Remove(output.Path));
        }

        Assert.AreEqual(0, fileList.Count);
    }

    [TestMethod]
    [DataRow("SHA1", false, false, false)]
    [DataRow("SHA256", false, false, false)]
    [DataRow("SHA1", false, false, true)]
    [DataRow("SHA256", false, false, true)]
    [DataRow("SHA1", true, false, false)]
    [DataRow("SHA256", true, false, false)]
    [DataRow("SHA1", false, true, false)]
    [DataRow("SHA256", false, true, false)]
    public async Task ConcurrentValidatorUsesSelectedAlgorithmAndRejectsMissingHashesAsync(string algorithmName, bool corrupt, bool missing, bool reverse)
    {
        var algorithm = AlgorithmName.FromString(algorithmName);
        using var sha1Input = new MemoryStream(Encoding.UTF8.GetBytes("actual multihash payload"));
        using var sha256Input = new MemoryStream(Encoding.UTF8.GetBytes("actual multihash payload"));
        var sha1 = Convert.ToHexString(AlgorithmName.SHA1.ComputeHash(sha1Input));
        var sha256 = Convert.ToHexString(AlgorithmName.SHA256.ComputeHash(sha256Input));
        var actual = algorithm == AlgorithmName.SHA1 ? sha1 : sha256;
        var expected = corrupt ? new string('0', actual.Length) : actual;
        var manifestChecksums = new[]
        {
            new Checksum { Algorithm = AlgorithmName.SHA256, ChecksumValue = algorithm == AlgorithmName.SHA256 ? expected : sha256 },
            new Checksum { Algorithm = AlgorithmName.SHA1, ChecksumValue = algorithm == AlgorithmName.SHA1 ? expected : sha1 },
        };
        if (reverse)
        {
            Array.Reverse(manifestChecksums);
        }

        var files = Channel.CreateUnbounded<InternalSbomFileInfo>();
        await files.Writer.WriteAsync(new InternalSbomFileInfo
        {
            Path = "payload.txt",
            FileLocation = FileLocation.InSbomFile,
            Checksum = missing ? Array.Empty<Checksum>() : manifestChecksums,
        });
        await files.Writer.WriteAsync(new InternalSbomFileInfo
        {
            Path = "payload.txt",
            FileLocation = FileLocation.OnDisk,
            Checksum = missing ? Array.Empty<Checksum>() : new[] { new Checksum { Algorithm = algorithm, ChecksumValue = actual.ToLowerInvariant() } },
        });
        files.Writer.Complete();
        var configuration = new Mock<IConfiguration>();
        configuration.SetupGet(c => c.HashAlgorithm).Returns(new ConfigurationSetting<AlgorithmName> { Value = algorithm });
        var validator = new ConcurrentHashValidator(new FileHashesDictionary(new ConcurrentDictionary<string, FileHashes>()), configuration.Object);
        var (output, errors) = validator.Validate(files);
        var successes = 0;
        var failures = 0;
        await foreach (var result in output.ReadAllAsync())
        {
            successes++;
            Assert.AreEqual("payload.txt", result.Path);
        }

        await foreach (var error in errors.ReadAllAsync())
        {
            failures++;
            Assert.AreEqual(ErrorType.InvalidHash, error.ErrorType);
        }

        Assert.AreEqual(corrupt || missing ? 0 : 1, successes);
        Assert.IsTrue(corrupt || missing ? failures > 0 : failures == 0);
    }
}
