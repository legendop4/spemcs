using System;
using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace Spemcs.Agent.Core.Network;

/// <summary>
/// Resolves signed key_id to trusted public RSA keys.
/// </summary>
public interface ITrustedKeyStore
{
    RSA? GetPublicKey(string keyId);
    void RegisterPublicKey(string keyId, RSA rsa, bool isRevoked = false);
    void RegisterPublicKeyPem(string keyId, string spkiPem, bool isRevoked = false);
    void RevokeKey(string keyId, string reason = "");
    bool IsRevoked(string keyId);
    IReadOnlyCollection<string> GetActiveKeyIds();
    IReadOnlyCollection<string> GetRevokedKeyIds();
}

public sealed class TrustedKeyStore : ITrustedKeyStore
{
    private readonly ConcurrentDictionary<string, RSA> _keys = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, string> _revokedKeys = new(StringComparer.Ordinal);

    public RSA? GetPublicKey(string keyId)
    {
        if (string.IsNullOrWhiteSpace(keyId)) return null;
        if (IsRevoked(keyId)) return null;
        return _keys.TryGetValue(keyId, out var key) ? key : null;
    }

    public void RegisterPublicKey(string keyId, RSA rsa, bool isRevoked = false)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyId);
        ArgumentNullException.ThrowIfNull(rsa);
        _keys[keyId] = rsa;
        if (isRevoked)
        {
            _revokedKeys[keyId] = "Registered as revoked";
        }
    }

    public void RegisterPublicKeyPem(string keyId, string spkiPem, bool isRevoked = false)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyId);
        ArgumentException.ThrowIfNullOrWhiteSpace(spkiPem);

        var rsa = RSA.Create();
        rsa.ImportFromPem(spkiPem);
        _keys[keyId] = rsa;
        if (isRevoked)
        {
            _revokedKeys[keyId] = "Registered as revoked";
        }
    }

    public void RevokeKey(string keyId, string reason = "")
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyId);
        _revokedKeys[keyId] = string.IsNullOrWhiteSpace(reason) ? "Revoked by administrator" : reason;
    }

    public bool IsRevoked(string keyId)
    {
        if (string.IsNullOrWhiteSpace(keyId)) return false;
        return _revokedKeys.ContainsKey(keyId);
    }

    public IReadOnlyCollection<string> GetActiveKeyIds()
    {
        return _keys.Keys.Where(k => !IsRevoked(k)).ToList();
    }

    public IReadOnlyCollection<string> GetRevokedKeyIds()
    {
        return _revokedKeys.Keys.ToList();
    }
}
