using System;
using System.Buffers;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Tasks;

namespace DevilGuard.Patcher
{
    internal sealed class UpdateManifest
    {
        public string Version { get; set; } = string.Empty;
        public string PackageUrl { get; set; } = string.Empty;
        public string Sha256 { get; set; } = string.Empty;
        public string FileName { get; set; } = string.Empty;
    }

    internal static class Program
    {
        private const long MaximumManifestBytes = 1024 * 1024;
        private const long MaximumPackageBytes = 512L * 1024 * 1024;

        private static readonly HttpClient Client = new HttpClient
        {
            Timeout = TimeSpan.FromMinutes(10)
        };

        private static async Task<int> Main(string[] args)
        {
            if (args.Length < 2)
            {
                Console.Error.WriteLine("Usage: DevilGuard.Patcher <https-manifest-url> <staging-directory>");
                Console.Error.WriteLine("The patcher downloads and SHA-256 verifies a package. It never executes the package automatically.");
                return 2;
            }

            try
            {
                Uri manifestUri = RequireHttpsUri(args[0], "manifest URL");
                string stagingDirectory = Path.GetFullPath(args[1]);
                Directory.CreateDirectory(stagingDirectory);

                UpdateManifest manifest = await DownloadManifestAsync(manifestUri).ConfigureAwait(false);
                ValidateManifest(manifest);

                Uri packageUri = RequireHttpsUri(manifest.PackageUrl, "package URL");
                string fileName = string.IsNullOrWhiteSpace(manifest.FileName)
                    ? Path.GetFileName(packageUri.LocalPath)
                    : Path.GetFileName(manifest.FileName);

                if (string.IsNullOrWhiteSpace(fileName))
                    throw new InvalidDataException("The update manifest does not provide a valid package file name.");

                string destinationPath = Path.Combine(stagingDirectory, fileName);
                string temporaryPath = destinationPath + ".download";

                Console.WriteLine("Downloading Devil-Guard " + manifest.Version + "...");
                string actualHash;
                try
                {
                    actualHash = await DownloadAndHashAsync(packageUri, temporaryPath).ConfigureAwait(false);
                    string expectedHash = NormalizeHash(manifest.Sha256);

                    if (!CryptographicOperations.FixedTimeEquals(
                        Convert.FromHexString(actualHash),
                        Convert.FromHexString(expectedHash)))
                    {
                        throw new CryptographicException("The downloaded package SHA-256 hash does not match the manifest.");
                    }

                    File.Move(temporaryPath, destinationPath, true);
                }
                catch
                {
                    if (File.Exists(temporaryPath))
                        File.Delete(temporaryPath);
                    throw;
                }
                Console.WriteLine("Verified package staged at: " + destinationPath);
                Console.WriteLine("SHA-256: " + actualHash);
                Console.WriteLine("The package was not executed. Review and code-sign it before deployment.");
                return 0;
            }
            catch (Exception exception)
            {
                Console.Error.WriteLine("Update failed: " + exception.Message);
                return 1;
            }
        }

        private static async Task<UpdateManifest> DownloadManifestAsync(Uri manifestUri)
        {
            using HttpResponseMessage response = await Client.GetAsync(manifestUri, HttpCompletionOption.ResponseHeadersRead).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();
            if (response.Content.Headers.ContentLength > MaximumManifestBytes)
                throw new InvalidDataException("The update manifest is larger than the allowed limit.");

            await using Stream stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
            using MemoryStream manifestBuffer = new MemoryStream();
            byte[] buffer = ArrayPool<byte>.Shared.Rent(8192);
            try
            {
                long totalBytes = 0;
                int bytesRead;
                while ((bytesRead = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length)).ConfigureAwait(false)) > 0)
                {
                    totalBytes += bytesRead;
                    if (totalBytes > MaximumManifestBytes)
                        throw new InvalidDataException("The update manifest exceeded the allowed limit while downloading.");
                    await manifestBuffer.WriteAsync(buffer.AsMemory(0, bytesRead)).ConfigureAwait(false);
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }

            UpdateManifest manifest = JsonSerializer.Deserialize<UpdateManifest>(manifestBuffer.ToArray(), new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            });

            return manifest ?? throw new InvalidDataException("The update manifest is empty or invalid JSON.");
        }

        private static async Task<string> DownloadAndHashAsync(Uri packageUri, string temporaryPath)
        {
            using HttpResponseMessage response = await Client.GetAsync(packageUri, HttpCompletionOption.ResponseHeadersRead).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();
            if (response.Content.Headers.ContentLength > MaximumPackageBytes)
                throw new InvalidDataException("The update package is larger than the allowed limit.");

            await using Stream input = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
            await using FileStream output = new FileStream(temporaryPath, FileMode.Create, FileAccess.Write, FileShare.None, 81920, true);
            using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

            byte[] buffer = ArrayPool<byte>.Shared.Rent(81920);
            try
            {
                int bytesRead;
                long totalBytes = 0;
                while ((bytesRead = await input.ReadAsync(buffer.AsMemory(0, buffer.Length)).ConfigureAwait(false)) > 0)
                {
                    totalBytes += bytesRead;
                    if (totalBytes > MaximumPackageBytes)
                        throw new InvalidDataException("The update package exceeded the allowed limit while downloading.");

                    hash.AppendData(buffer, 0, bytesRead);
                    await output.WriteAsync(buffer.AsMemory(0, bytesRead)).ConfigureAwait(false);
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }

            return Convert.ToHexString(hash.GetHashAndReset());
        }

        private static void ValidateManifest(UpdateManifest manifest)
        {
            if (string.IsNullOrWhiteSpace(manifest.Version))
                throw new InvalidDataException("The update manifest is missing a version.");
            if (string.IsNullOrWhiteSpace(manifest.PackageUrl))
                throw new InvalidDataException("The update manifest is missing a package URL.");

            string normalizedHash = NormalizeHash(manifest.Sha256);
            if (normalizedHash.Length != 64)
                throw new InvalidDataException("The update manifest SHA-256 value must contain exactly 64 hexadecimal characters.");

            _ = Convert.FromHexString(normalizedHash);
        }

        private static Uri RequireHttpsUri(string value, string description)
        {
            if (!Uri.TryCreate(value, UriKind.Absolute, out Uri uri))
                throw new ArgumentException("The " + description + " is not a valid absolute URL.");

            if (!string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("The " + description + " must use HTTPS.");

            return uri;
        }

        private static string NormalizeHash(string value) =>
            (value ?? string.Empty).Replace("-", string.Empty).Replace(" ", string.Empty).Trim().ToUpperInvariant();
    }
}
