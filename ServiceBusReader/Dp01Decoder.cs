using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ServiceBusReader;

public sealed record FileMetadata(
    [property: JsonPropertyName("fileName")] string? FileName,
    [property: JsonPropertyName("fileExtension")] string? FileExtension,
    [property: JsonPropertyName("contentType")] string? ContentType,
    [property: JsonPropertyName("fileSize")] long FileSize,
    [property: JsonPropertyName("sha256")] string? Sha256);

public sealed record DecodedFile(FileMetadata Metadata, byte[] Content);

/// <summary>Thrown for any message that must not be processed (bad format, auth failure, integrity failure).</summary>
public sealed class InvalidMessageException(string message, Exception? inner = null) : Exception(message, inner);

/// <summary>
/// DP01 envelope:
///   body       = "DP01"(4) | nonce(12) | tag(16) | ciphertext
///   AAD        = ASCII "DP01"
///   plaintext  = int32 LE metadataLength | UTF-8 JSON metadata | original file bytes
/// </summary>
public static class Dp01Decoder
{
    public const string EncryptedSubject = "encrypted-file";
    public const string PlainSubject = "file";
    public const string EncryptionProperty = "encryption";
    public const string EncryptionValue = "AES-256-GCM/DP01";

    private static readonly byte[] Marker = "DP01"u8.ToArray();
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int HeaderSize = 4 + NonceSize + TagSize; // 32

    public static byte[] LoadKey(DecryptionOptions options)
    {
        var base64 = options.KeyBase64;
        if (string.IsNullOrWhiteSpace(base64) && !string.IsNullOrWhiteSpace(options.KeyFile))
            base64 = File.ReadAllText(options.KeyFile);

        if (string.IsNullOrWhiteSpace(base64))
            throw new InvalidOperationException("Decryption key not configured (Decryption:KeyBase64 or Decryption:KeyFile).");

        byte[] key;
        try { key = Convert.FromBase64String(base64.Trim()); }
        catch (FormatException e) { throw new InvalidOperationException("Decryption key is not valid Base64.", e); }

        if (key.Length != 32)
            throw new InvalidOperationException($"Decryption key must decode to 32 bytes, got {key.Length}.");
        return key;
    }

    public static DecodedFile DecryptAndParse(ReadOnlySpan<byte> body, byte[] key)
    {
        if (body.Length < HeaderSize)
            throw new InvalidMessageException($"Body is {body.Length} bytes; DP01 requires at least {HeaderSize}.");
        if (!body[..4].SequenceEqual(Marker))
            throw new InvalidMessageException("Body does not start with the DP01 marker.");

        var nonce = body.Slice(4, NonceSize);
        var tag = body.Slice(4 + NonceSize, TagSize);
        var ciphertext = body[HeaderSize..];
        var plaintext = new byte[ciphertext.Length];

        try
        {
            using var aes = new AesGcm(key, TagSize);
            aes.Decrypt(nonce, ciphertext, tag, plaintext, Marker);
        }
        catch (AuthenticationTagMismatchException e)
        {
            // Never use unauthenticated plaintext.
            CryptographicOperations.ZeroMemory(plaintext);
            throw new InvalidMessageException("AES-GCM authentication failed.", e);
        }

        return ParsePlaintext(plaintext);
    }

    private static DecodedFile ParsePlaintext(byte[] plaintext)
    {
        if (plaintext.Length < 4)
            throw new InvalidMessageException("Plaintext too short for metadata length prefix.");

        int metaLength = BinaryPrimitives.ReadInt32LittleEndian(plaintext.AsSpan(0, 4));
        int remaining = plaintext.Length - 4;
        if (metaLength < 0 || metaLength > remaining)
            throw new InvalidMessageException($"Invalid metadata length {metaLength} (remaining {remaining}).");

        FileMetadata? metadata;
        try
        {
            var json = Encoding.UTF8.GetString(plaintext, 4, metaLength);
            metadata = JsonSerializer.Deserialize<FileMetadata>(json);
        }
        catch (Exception e) when (e is JsonException or ArgumentException)
        {
            throw new InvalidMessageException("Metadata is not valid UTF-8 JSON.", e);
        }
        if (metadata is null)
            throw new InvalidMessageException("Metadata JSON is empty.");

        var content = plaintext.AsSpan(4 + metaLength).ToArray();
        Verify(metadata, content);
        return new DecodedFile(metadata, content);
    }

    /// <summary>Checks the declared size and SHA-256 against the file bytes.</summary>
    public static void Verify(FileMetadata metadata, byte[] content)
    {
        if (metadata.FileSize != content.Length)
            throw new InvalidMessageException($"Size mismatch: metadata {metadata.FileSize}, actual {content.Length}.");

        var actual = Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant();
        if (!string.Equals(actual, metadata.Sha256, StringComparison.Ordinal))
            throw new InvalidMessageException($"SHA-256 mismatch: metadata {metadata.Sha256}, actual {actual}.");
    }

    /// <summary>Reduces an untrusted file name to a safe basename.</summary>
    public static string SanitizeFileName(string? fileName)
    {
        var name = Path.GetFileName((fileName ?? "").Replace('\\', '/'));
        var invalid = Path.GetInvalidFileNameChars();
        name = new string(name.Select(c => invalid.Contains(c) || char.IsControl(c) ? '_' : c).ToArray()).Trim(' ', '.');
        return string.IsNullOrEmpty(name) ? "unnamed" : name;
    }
}
