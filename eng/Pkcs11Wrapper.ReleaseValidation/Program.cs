using System.IO.Compression;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml.Linq;

if (args.Length != 2)
{
    Console.Error.WriteLine("Usage: dotnet run --project eng/Pkcs11Wrapper.ReleaseValidation -- <package-dir> <version>");
    return 2;
}

string packageDirectory = Path.GetFullPath(args[0]);
string version = args[1];

if (!Directory.Exists(packageDirectory))
{
    Console.Error.WriteLine($"Package directory does not exist: {packageDirectory}");
    return 2;
}

try
{
    ValidatePackage(packageDirectory, "Pkcs11Wrapper", version);
    ValidatePackage(packageDirectory, "Pkcs11Wrapper.Native", version);
    ValidatePackage(packageDirectory, "Pkcs11Wrapper.ThalesLuna.Native", version);
    ValidatePackage(packageDirectory, "Pkcs11Wrapper.ThalesLuna", version);
    Console.WriteLine("Package layout, README, SourceLink, and symbol validation completed successfully.");
    return 0;
}
catch (Exception ex)
{
    Console.Error.WriteLine($"Release package validation failed: {ex.Message}");
    return 1;
}

static void ValidatePackage(string packageDirectory, string packageId, string version)
{
    string nupkgPath = Path.Combine(packageDirectory, $"{packageId}.{version}.nupkg");
    string snupkgPath = Path.Combine(packageDirectory, $"{packageId}.{version}.snupkg");

    ValidateMainPackage(nupkgPath, packageId, version);
    ValidateSymbolsPackage(snupkgPath, packageId);
}

static void ValidateMainPackage(string packagePath, string packageId, string expectedVersion)
{
    if (!File.Exists(packagePath))
    {
        throw new InvalidOperationException($"Missing package: {packagePath}");
    }

    using ZipArchive archive = ZipFile.OpenRead(packagePath);
    string assemblyName = packageId + ".dll";
    const string readmePath = "README.nuget.md";
    RequireEntry(archive, readmePath);
    RequireEntry(archive, $"lib/net10.0/{assemblyName}");

    ZipArchiveEntry nuspecEntry = archive.Entries.FirstOrDefault(entry => entry.FullName.EndsWith(".nuspec", StringComparison.Ordinal))
        ?? throw new InvalidOperationException($"{packageId} package is missing a .nuspec file.");

    using Stream nuspecStream = nuspecEntry.Open();
    XDocument nuspec = XDocument.Load(nuspecStream);
    XElement? metadata = nuspec.Root?.Element(XName.Get("metadata", nuspec.Root.Name.NamespaceName));
    XElement? version = metadata?.Element(XName.Get("version", nuspec.Root!.Name.NamespaceName));
    XElement? repository = metadata?.Element(XName.Get("repository", nuspec.Root!.Name.NamespaceName));
    if (version is null || string.IsNullOrWhiteSpace(version.Value))
    {
        throw new InvalidOperationException($"{packageId} package is missing version metadata.");
    }

    string nuspecVersion = version.Value.Trim();
    if (!string.Equals(nuspecVersion, expectedVersion, StringComparison.Ordinal))
    {
        throw new InvalidOperationException($"{packageId} nuspec version '{nuspecVersion}' does not match expected release version '{expectedVersion}'.");
    }

    if (repository is null)
    {
        throw new InvalidOperationException($"{packageId} package is missing repository metadata.");
    }

    string? repositoryType = repository.Attribute("type")?.Value;
    string? repositoryUrl = repository.Attribute("url")?.Value;
    if (!string.Equals(repositoryType, "git", StringComparison.OrdinalIgnoreCase))
    {
        throw new InvalidOperationException($"{packageId} package repository type must be 'git'.");
    }

    if (!string.Equals(repositoryUrl, "https://github.com/EbubekirERGUN/Pkcs11Wrapper", StringComparison.Ordinal))
    {
        throw new InvalidOperationException($"{packageId} package repository URL is unexpected: {repositoryUrl}");
    }

    string readme = ReadEntryText(archive, readmePath);
    ValidateReadmeLinks(packageId, readme);
}

static void ValidateSymbolsPackage(string packagePath, string packageId)
{
    if (!File.Exists(packagePath))
    {
        throw new InvalidOperationException($"Missing symbols package: {packagePath}");
    }

    using ZipArchive archive = ZipFile.OpenRead(packagePath);
    ZipArchiveEntry pdbEntry = archive.Entries.FirstOrDefault(entry => entry.FullName.EndsWith($"/{packageId}.pdb", StringComparison.Ordinal))
        ?? archive.Entries.FirstOrDefault(entry => string.Equals(Path.GetFileName(entry.FullName), $"{packageId}.pdb", StringComparison.Ordinal))
        ?? throw new InvalidOperationException($"{packageId} symbols package does not contain {packageId}.pdb.");

    using MemoryStream pdbStream = new();
    using (Stream source = pdbEntry.Open())
    {
        source.CopyTo(pdbStream);
    }

    pdbStream.Position = 0;
    using MetadataReaderProvider provider = MetadataReaderProvider.FromPortablePdbStream(pdbStream, MetadataStreamOptions.LeaveOpen);
    MetadataReader reader = provider.GetMetadataReader();
    Guid sourceLinkGuid = new("CC110556-A091-4D38-9FEC-25AB9A351A6A");
    ModuleDefinitionHandle moduleHandle = (ModuleDefinitionHandle)MetadataTokens.Handle(1);

    foreach (CustomDebugInformationHandle handle in reader.GetCustomDebugInformation(moduleHandle))
    {
        CustomDebugInformation info = reader.GetCustomDebugInformation(handle);
        if (reader.GetGuid(info.Kind) != sourceLinkGuid)
        {
            continue;
        }

        string sourceLinkJson = Encoding.UTF8.GetString(reader.GetBlobBytes(info.Value));
        if (!sourceLinkJson.Contains("raw.githubusercontent.com/EbubekirERGUN/Pkcs11Wrapper/", StringComparison.Ordinal))
        {
            throw new InvalidOperationException($"{packageId} PDB does not contain the expected GitHub SourceLink mapping.");
        }

        return;
    }

    throw new InvalidOperationException($"{packageId} PDB does not contain SourceLink custom debug information.");
}

static void ValidateReadmeLinks(string packageId, string markdown)
{
    Regex markdownLinkRegex = new(@"(?<!!)(?:\[[^\]]+\])\(([^)]+)\)", RegexOptions.Compiled);
    List<string> invalidLinks = [];

    foreach (Match match in markdownLinkRegex.Matches(markdown))
    {
        string target = match.Groups[1].Value.Trim();
        if (target.StartsWith('#') ||
            target.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
            target.StartsWith("https://", StringComparison.OrdinalIgnoreCase) ||
            target.StartsWith("mailto:", StringComparison.OrdinalIgnoreCase))
        {
            continue;
        }

        invalidLinks.Add(target);
    }

    if (invalidLinks.Count > 0)
    {
        throw new InvalidOperationException($"{packageId} README contains package-unsafe relative links: {string.Join(", ", invalidLinks)}");
    }
}

static void RequireEntry(ZipArchive archive, string path)
{
    if (archive.GetEntry(path) is null)
    {
        throw new InvalidOperationException($"Archive {archive} is missing required entry '{path}'.");
    }
}

static string ReadEntryText(ZipArchive archive, string path)
{
    ZipArchiveEntry entry = archive.GetEntry(path)
        ?? throw new InvalidOperationException($"Archive is missing required entry '{path}'.");

    using Stream stream = entry.Open();
    using StreamReader reader = new(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
    return reader.ReadToEnd();
}
