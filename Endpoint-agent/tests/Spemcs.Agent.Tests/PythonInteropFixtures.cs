using System;
using Spemcs.Agent.Core.Network;

namespace Spemcs.Agent.Tests;

/// <summary>
/// Cross-language interop fixtures: policy payloads signed by the REAL backend signer
/// (<c>backend/backend/services/policy_signer.py</c> + <c>canonical_json.py</c>).
/// <para>
/// These are the only tests that can prove RFC 8785 canonicalization and
/// RSA-PSS / SHA-256 / MGF1-SHA-256 / salt-length-32 actually agree between Python and
/// .NET 8. A test where C# both signs and verifies would pass even if both ends were
/// consistently wrong.
/// </para>
/// <para>
/// All three payloads are signed by the SAME ephemeral RSA-2048 key, so one
/// <see cref="TrustedKeyStore"/> registration covers them. Only the public half is
/// embedded; the private key existed in memory for the duration of fixture generation and
/// was never written to disk or committed.
/// </para>
/// <para>
/// To regenerate (e.g. if the payload shape changes): build the payload with
/// <c>create_canonical_payload(...)</c>, canonicalize with <c>canonicalize_to_bytes</c>,
/// sign with <c>PolicySigner.sign_payload</c>, and embed the canonical bytes verbatim.
/// The C# verifier checks the signature over the RAW JSON bytes as received, so the
/// string below must stay byte-identical to what was signed - reformatting it, even just
/// adding whitespace, will turn every test in this fixture into an InvalidSignature failure.
/// </para>
/// </summary>
internal static class PythonInteropFixtures
{
    /// <summary>key_id embedded in all three payloads.</summary>
    public const string KeyId = "dev-key-1";

    /// <summary>SPKI public key for <see cref="KeyId"/>.</summary>
    public const string PublicKeyPem = @"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArzJn4YKRVnGIDp0FUvIW
bJAfK5YKCQTeZezh1kgYQOOw3xAdFPhJrXNtHCGtk1MAzSWYevdRovqljOl5KB9w
3cRwHLB2IknNHjbCPeKpMZMAUt8XG3VC3lhGNXZfV1IiFaBMQtJffpGb6cLw9In6
D2sHMdNGVMFyCfQnAFSokKzbKcfJAygkHlBqHBYZ4Lxpua5mss81Wp2lbZNYnxRF
VBc+yXmZBYmPkBop9MwdB3lWH7Vzk54Tx2vHClb9n2tVGX+C2oaRZJo2kX4y6f6U
HCOGynVb9769u/Lffu9aiKmH3VuLn5fWVCLZGnoOBj8d7Lt7lgb2Kxv6kuZpb0Bx
nwIDAQAB
-----END PUBLIC KEY-----
";

    /// <summary>Exam the payloads are bound to.</summary>
    public static readonly Guid ExamId = Guid.Parse("11111111-2222-3333-4444-555555555555");

    /// <summary>Policy id shared by all three payloads.</summary>
    public static readonly Guid PolicyId = Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");

    /// <summary>A time inside the signed validity window [2026-01-01, 2030-01-01).</summary>
    public static readonly DateTimeOffset ValidEvalTime = new(2026, 9, 3, 12, 0, 0, TimeSpan.Zero);

    // =====================================================================================
    // A. Well-formed schema 1.1 policy. MUST be ACCEPTED.
    // =====================================================================================

    public const string ValidRawJson = "{\"allowed_destinations\":[{\"domains\":[\"test.example.com\"],\"ip_ranges\":[\"192.168.1.0/24\"],\"name\":\"TestVendor\",\"tcp_ports\":[443],\"udp_ports\":[]}],\"approved_browser\":\"chrome\",\"exam_id\":\"11111111-2222-3333-4444-555555555555\",\"expires_at\":\"2030-01-01T00:00:00Z\",\"key_id\":\"dev-key-1\",\"management_server\":{\"ip_addresses\":[\"127.0.0.1\"],\"port\":8000},\"not_before\":\"2026-01-01T00:00:00Z\",\"policy_id\":\"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\",\"schema_version\":\"1.1\",\"vendor_profile_id\":null,\"version\":1}";

    public const string ValidSignatureBase64 = "IDrd8F6N3MFq3PA3iObrZSy4kQ8ZkAv3VzSU/TZ0bLQQ5uS9DDUmPKKV2K3bUEly86UQp49+nzFrNG5jlwndRd1P6ScN9/+M4PM8WuTXPG4WWe1frc7r2R3DZFHupPP/AoeiVncq3WIhp8iaQnfxag/Tu76idnBx82I/w9yk9Hyy8YKFaxoaMTb0mWn877wd11JyyNSae92AtXjnZnis+jV3ybo67KuRu0r/gqHIkfYrkh6p8bM0CUKn265aRwZeHoePzEm0UOiM1gQZg83p9fYDo+lbqUSI1gzdtlLIngX5TW3bmikQVWffcasOLB90VuNeX633QjovowkFgBQALQ==";

    // =====================================================================================
    // B. What a PRE-1.1 backend emits: schema_version "1.0" and NO approved_browser field.
    //    The signature is genuinely valid, so the only thing standing between this policy and
    //    an UNSCOPED firewall allow rule is the agent's schema / mandatory-field contract.
    //    MUST be REJECTED (requirements 4 and 5).
    // =====================================================================================

    public const string LegacySchema10RawJson = "{\"allowed_destinations\":[{\"domains\":[\"test.example.com\"],\"ip_ranges\":[\"192.168.1.0/24\"],\"name\":\"TestVendor\",\"tcp_ports\":[443],\"udp_ports\":[]}],\"exam_id\":\"11111111-2222-3333-4444-555555555555\",\"expires_at\":\"2030-01-01T00:00:00Z\",\"key_id\":\"dev-key-1\",\"management_server\":{\"ip_addresses\":[\"127.0.0.1\"],\"port\":8000},\"not_before\":\"2026-01-01T00:00:00Z\",\"policy_id\":\"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\",\"schema_version\":\"1.0\",\"vendor_profile_id\":null,\"version\":1}";

    public const string LegacySchema10SignatureBase64 = "RaLpPBatLM4Dda3Gv9ZSyxp2eom4hiX2jb7/5crJhr7vuBxgmV1e0gaAZXpgBhcEJ34I0ol48//YX1rhFDWzqkVoPJr5NY4PjRxt9TPDSiME5SmY+oRCXQsyWRugImnjlOBzbrRlk1Q+5OT+/F06iy80pekiYu4eUNlO5vI9UqEZKlvOSKC7F105xGDRNK3r3WPa+kYmMqLNyXogLkgY2dcG23XNJ8zxuaGqM5klhdIjX7cd+av0aeTb50EFG5ndAe2vsrxeSLr8z3zdRsDGfFmS9gy+K+BIDD1EBz+lL+0uZNsvwx+uEYw4cKWDxYqBHkCRlwEQbnGlY0D7LVGHFg==";

    // =====================================================================================
    // C. Schema 1.1, correctly signed, but names a browser family the endpoint has no
    //    approval branch for (Firefox is listed in KnownUnapprovedBrowserExes). MUST be
    //    REJECTED, and specifically AFTER the signature verifies - proving the refusal comes
    //    from the policy contract rather than from a crypto failure.
    // =====================================================================================

    public const string UnscopableBrowserRawJson = "{\"allowed_destinations\":[{\"domains\":[\"test.example.com\"],\"ip_ranges\":[\"192.168.1.0/24\"],\"name\":\"TestVendor\",\"tcp_ports\":[443],\"udp_ports\":[]}],\"approved_browser\":\"firefox\",\"exam_id\":\"11111111-2222-3333-4444-555555555555\",\"expires_at\":\"2030-01-01T00:00:00Z\",\"key_id\":\"dev-key-1\",\"management_server\":{\"ip_addresses\":[\"127.0.0.1\"],\"port\":8000},\"not_before\":\"2026-01-01T00:00:00Z\",\"policy_id\":\"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\",\"schema_version\":\"1.1\",\"vendor_profile_id\":null,\"version\":1}";

    public const string UnscopableBrowserSignatureBase64 = "Hdm7B9aJR9lsH5YcnRmtCDx26kRL2Va7OWO00YdnnAy/R80naybAFmsNakOl3OD8RLfUxrj0814oXW2csbdb/Ogyv7/GnTyMDpMiOSzrdN4tq+FFZHcEjdGEZfB44mIRlSYf1kYh/IyTgpK4o6sZ3cv5oWLUQErbSjiWbiiTokz92AifaEzDut08HfadDWpEU87czaFabq44HQfjKLxPz6DaJgoH+gY9Qj0mAfjxQfxS7IPk2TbUGDKLlphE65i3JNEbp9eREWTG1fCn+MwaL8LgCM7apwurkCqG5qMa9gYP+PrAa8hOlSbueneg4f22dQawpDEKrcc9Fc2u5KNzNA==";

    // =====================================================================================
    // Envelope helpers
    // =====================================================================================

    private static SignedPolicyMessage Envelope(string rawJson, string signature) => new(
        MessageType: "SIGNED_NETWORK_POLICY",
        ProtocolVersion: 1,
        RawPolicyJson: rawJson,
        SignatureBase64: signature
    );

    /// <summary>Fixture A wrapped in a wire envelope.</summary>
    public static SignedPolicyMessage ValidMessage() => Envelope(ValidRawJson, ValidSignatureBase64);

    /// <summary>Fixture B wrapped in a wire envelope.</summary>
    public static SignedPolicyMessage LegacySchema10Message()
        => Envelope(LegacySchema10RawJson, LegacySchema10SignatureBase64);

    /// <summary>Fixture C wrapped in a wire envelope.</summary>
    public static SignedPolicyMessage UnscopableBrowserMessage()
        => Envelope(UnscopableBrowserRawJson, UnscopableBrowserSignatureBase64);
}
