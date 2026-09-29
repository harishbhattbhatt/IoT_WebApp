namespace ServiceBusReader;

public sealed class ServiceBusOptions
{
    /// <summary>Listen-only connection string for the namespace.</summary>
    public string ConnectionString { get; set; } = "";

    /// <summary>Queue to receive from. Ignored when TopicName is set.</summary>
    public string QueueName { get; set; } = "";

    /// <summary>Optional: receive from an existing subscription on this topic instead of a queue.</summary>
    public string TopicName { get; set; } = "";
    public string SubscriptionName { get; set; } = "";

    public int MaxConcurrentCalls { get; set; } = 1;

    public bool UseTopic => !string.IsNullOrWhiteSpace(TopicName);
}

public sealed class DecryptionOptions
{
    /// <summary>AES-256-GCM key, Base64 (32 decoded bytes). Prefer an env var / secret store.</summary>
    public string KeyBase64 { get; set; } = "";

    /// <summary>Alternative: path to a file containing the Base64 key.</summary>
    public string KeyFile { get; set; } = "";
}

public sealed class OutputOptions
{
    public string Directory { get; set; } = "received";
}
