using System.IO.Compression;
using Azure.Messaging.ServiceBus;
using Microsoft.Extensions.Configuration;
using ServiceBusReader;

// config.json (git-ignored) + environment variables, e.g. ServiceBus__ConnectionString, Decryption__KeyBase64
var config = new ConfigurationBuilder()
    .SetBasePath(AppContext.BaseDirectory)
    .AddJsonFile("config.json", optional: true)
    .AddJsonFile(Path.Combine(Directory.GetCurrentDirectory(), "config.json"), optional: true)
    .AddEnvironmentVariables()
    .Build();

var sb = config.GetSection("ServiceBus").Get<ServiceBusOptions>() ?? new();
var decryption = config.GetSection("Decryption").Get<DecryptionOptions>() ?? new();
var output = config.GetSection("Output").Get<OutputOptions>() ?? new();

if (string.IsNullOrWhiteSpace(sb.ConnectionString))
{
    Console.Error.WriteLine("ServiceBus:ConnectionString is not set. Copy config.example.json to config.json and fill it in.");
    return 1;
}
if (!sb.UseTopic && string.IsNullOrWhiteSpace(sb.QueueName))
{
    Console.Error.WriteLine("Set ServiceBus:QueueName (or TopicName + SubscriptionName).");
    return 1;
}
if (sb.UseTopic && string.IsNullOrWhiteSpace(sb.SubscriptionName))
{
    Console.Error.WriteLine("ServiceBus:SubscriptionName is required when TopicName is set.");
    return 1;
}

byte[]? key = null;
try { key = Dp01Decoder.LoadKey(decryption); }
catch (InvalidOperationException e) { Console.WriteLine($"[warn] {e.Message} Encrypted messages will be abandoned."); }

var outputDir = Path.GetFullPath(output.Directory);
Directory.CreateDirectory(outputDir);

await using var client = new ServiceBusClient(sb.ConnectionString);
var processorOptions = new ServiceBusProcessorOptions
{
    AutoCompleteMessages = false, // complete only after successful processing
    MaxConcurrentCalls = Math.Max(1, sb.MaxConcurrentCalls),
    ReceiveMode = ServiceBusReceiveMode.PeekLock,
};
await using var processor = sb.UseTopic
    ? client.CreateProcessor(sb.TopicName, sb.SubscriptionName, processorOptions)
    : client.CreateProcessor(sb.QueueName, processorOptions);

processor.ProcessMessageAsync += async args =>
{
    var msg = args.Message;
    try
    {
        var file = Decode(msg, key);
        var path = await SaveAsync(file, outputDir, args.CancellationToken);
        Console.WriteLine($"[ok]   {msg.MessageId} -> {path} ({file.Metadata.FileSize} bytes, {file.Metadata.ContentType})");
        try { Describe(file); } catch (Exception e) { Console.WriteLine($"       (could not parse content: {e.Message})"); }
        await args.CompleteMessageAsync(msg, args.CancellationToken);
    }
    catch (Exception e) when (e is not OperationCanceledException)
    {
        // Leave the message to normal retry / dead-letter handling (MaxDeliveryCount).
        Console.Error.WriteLine($"[fail] {msg.MessageId} (delivery {msg.DeliveryCount}): {e.Message}");
        await args.AbandonMessageAsync(msg, cancellationToken: args.CancellationToken);
    }
};
processor.ProcessErrorAsync += args =>
{
    Console.Error.WriteLine($"[error] {args.ErrorSource} {args.EntityPath}: {args.Exception.Message}");
    return Task.CompletedTask;
};

using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

var entity = sb.UseTopic ? $"{sb.TopicName}/subscriptions/{sb.SubscriptionName}" : sb.QueueName;
Console.WriteLine($"Listening on '{entity}'. Files -> {outputDir}. Ctrl+C to stop.");
await processor.StartProcessingAsync(cts.Token);
try { await Task.Delay(Timeout.Infinite, cts.Token); } catch (OperationCanceledException) { }
Console.WriteLine("Stopping...");
await processor.StopProcessingAsync();
return 0;

static DecodedFile Decode(ServiceBusReceivedMessage msg, byte[]? key)
{
    var props = msg.ApplicationProperties;
    props.TryGetValue(Dp01Decoder.EncryptionProperty, out var encryption);

    if (msg.Subject == Dp01Decoder.EncryptedSubject)
    {
        if (encryption as string != Dp01Decoder.EncryptionValue)
            throw new InvalidMessageException($"Unsupported encryption '{encryption}'.");
        if (key is null)
            throw new InvalidMessageException("No decryption key configured.");
        return Dp01Decoder.DecryptAndParse(msg.Body.ToMemory().Span, key);
    }

    if (msg.Subject == Dp01Decoder.PlainSubject && encryption is null)
    {
        // Unencrypted: body is the original file; metadata comes from application properties.
        var content = msg.Body.ToArray();
        var metadata = new FileMetadata(
            Get(props, "fileName"),
            Get(props, "fileExtension"),
            Get(props, "contentType") ?? msg.ContentType,
            long.TryParse(Get(props, "fileSize"), out var size) ? size : content.Length,
            Get(props, "sha256"));
        if (metadata.Sha256 is not null)
            Dp01Decoder.Verify(metadata, content);
        return new DecodedFile(metadata, content);
    }

    // Never silently treat unknown messages as plaintext.
    throw new InvalidMessageException($"Unknown message: Subject='{msg.Subject}', encryption='{encryption}'.");
}

static string? Get(IReadOnlyDictionary<string, object> props, string name) =>
    props.TryGetValue(name, out var v) ? v?.ToString() : null;

static async Task<string> SaveAsync(DecodedFile file, string outputDir, CancellationToken ct)
{
    var name = Dp01Decoder.SanitizeFileName(file.Metadata.FileName);
    var path = Path.Combine(outputDir, name);
    var stem = Path.GetFileNameWithoutExtension(name);
    var ext = Path.GetExtension(name);
    for (var i = 1; File.Exists(path); i++)
        path = Path.Combine(outputDir, $"{stem} ({i}){ext}");

    await File.WriteAllBytesAsync(path, file.Content, ct);
    return path;
}

static void Describe(DecodedFile file)
{
    var ext = (file.Metadata.FileExtension ?? Path.GetExtension(file.Metadata.FileName ?? "")).TrimStart('.').ToLowerInvariant();
    var type = file.Metadata.ContentType ?? "";

    if (ext == "zip" || type.Contains("zip"))
    {
        using var zip = new ZipArchive(new MemoryStream(file.Content), ZipArchiveMode.Read);
        Console.WriteLine($"       zip with {zip.Entries.Count} entr{(zip.Entries.Count == 1 ? "y" : "ies")}");
        foreach (var entry in zip.Entries.Take(20))
            Console.WriteLine($"         {entry.FullName} ({entry.Length} bytes)");
    }
    else if (type.StartsWith("text/") || type.Contains("json") || ext is "json" or "txt" or "csv" or "xml")
    {
        var text = System.Text.Encoding.UTF8.GetString(file.Content);
        Console.WriteLine($"       preview: {(text.Length > 200 ? text[..200] + "..." : text)}");
    }
}
