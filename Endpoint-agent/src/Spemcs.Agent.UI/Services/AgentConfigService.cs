using System;
using System.IO;
using System.Text.Json;
using Spemcs.Agent.UI.Models;

namespace Spemcs.Agent.UI.Services;

public interface IAgentConfigService
{
    string ConfigFilePath { get; }
    bool Exists();
    AgentConfig? Load();
    void Save(AgentConfig config);
    void Delete();
}

public class AgentConfigService : IAgentConfigService
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true
    };

    public string ConfigFilePath { get; }

    public AgentConfigService(string? customPath = null)
    {
        if (!string.IsNullOrWhiteSpace(customPath))
        {
            ConfigFilePath = customPath;
        }
        else
        {
            var appData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            var dir = Path.Combine(appData, "SPEMCS", "Endpoint Agent");
            ConfigFilePath = Path.Combine(dir, "config.json");
        }
    }

    public bool Exists() => File.Exists(ConfigFilePath);

    public AgentConfig? Load()
    {
        try
        {
            if (!File.Exists(ConfigFilePath)) return null;

            var json = File.ReadAllText(ConfigFilePath);
            if (string.IsNullOrWhiteSpace(json)) return null;

            var config = JsonSerializer.Deserialize<AgentConfig>(json, JsonOptions);
            return config;
        }
        catch
        {
            // If config is corrupted, preserve backup and return null to prompt setup
            try
            {
                var backupPath = ConfigFilePath + ".corrupted." + DateTime.UtcNow.Ticks;
                if (File.Exists(ConfigFilePath))
                {
                    File.Move(ConfigFilePath, backupPath, true);
                }
            }
            catch { }
            return null;
        }
    }

    public void Save(AgentConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);

        var dir = Path.GetDirectoryName(ConfigFilePath);
        if (!string.IsNullOrWhiteSpace(dir))
        {
            Directory.CreateDirectory(dir);
        }

        var tempPath = ConfigFilePath + ".tmp." + Guid.NewGuid().ToString("N");
        var json = JsonSerializer.Serialize(config, JsonOptions);
        File.WriteAllText(tempPath, json);

        // Atomic replace or move
        if (File.Exists(ConfigFilePath))
        {
            File.Replace(tempPath, ConfigFilePath, null);
        }
        else
        {
            File.Move(tempPath, ConfigFilePath);
        }
    }

    public void Delete()
    {
        if (File.Exists(ConfigFilePath))
        {
            File.Delete(ConfigFilePath);
        }
    }
}
