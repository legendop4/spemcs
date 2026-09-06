using System;
using System.Threading;

namespace Spemcs.Agent.Service;

/// <summary>
/// Holds the device enrolment credentials this agent process speaks to the backend with.
/// </summary>
/// <remarks>
/// <para>
/// WHY THIS TYPE EXISTS. The backend issues a signed device token at registration
/// (<c>POST api/v1/devices/register</c>) and, from the Phase 19 hardening onwards, requires it on
/// every other agent REST call. Before that hardening the agent discarded the token: the
/// registration response was deserialised into a record that had no field for it, and the session
/// and event adapters sent no credential at all. Those three calls were accepted anonymously, so
/// nothing broke - which is precisely why the omission survived.
/// </para>
/// <para>
/// The token is process-scoped and deliberately NOT persisted. It has a 30-day lifetime and is
/// re-issued on every successful registration, which the agent performs at startup, so persisting
/// it would add a credential at rest on the examination workstation - the machine a candidate has
/// physical access to - in exchange for nothing. If the process restarts, it registers again.
/// </para>
/// <para>
/// The enrolment key is a different thing with a different lifetime: it is a shared bootstrap
/// secret that authorises registration itself, it is read from configuration, and it is never
/// written to a log. It must NOT be compiled into the agent - see the note on
/// <see cref="EnrollmentKey"/>.
/// </para>
/// <para>
/// Access is guarded because <c>AgentWorker</c>'s registration path and <c>EventUploaderWorker</c>'s
/// upload loop run concurrently on different threads: the uploader can be draining its backlog at
/// the moment registration completes and replaces the token.
/// </para>
/// </remarks>
public sealed class DeviceCredentialStore
{
    private readonly object _gate = new();
    private string? _deviceToken;

    /// <summary>
    /// Creates a credential store.
    /// </summary>
    /// <param name="enrollmentKey">
    /// The bootstrap enrolment key from configuration, or <see langword="null"/> when none is
    /// configured. A null key is not substituted with a default: the backend refuses registration
    /// outright when its own key is unset, and a client-side fallback would only turn a
    /// configuration error into a confusing 401.
    /// </param>
    public DeviceCredentialStore(string? enrollmentKey)
    {
        EnrollmentKey = string.IsNullOrWhiteSpace(enrollmentKey) ? null : enrollmentKey;
    }

    /// <summary>
    /// The bootstrap enrolment key, or <see langword="null"/> when unconfigured.
    /// </summary>
    /// <remarks>
    /// This value is supplied by configuration and must never be given a compiled-in default.
    /// A shared secret baked into a binary that is installed on every examination workstation is
    /// readable by anyone holding the binary, which makes it a secret in name only - and this key
    /// is what authorises a machine to obtain a device token in the first place.
    /// </remarks>
    public string? EnrollmentKey { get; }

    /// <summary>The device token issued by the most recent successful registration, if any.</summary>
    public string? DeviceToken
    {
        get { lock (_gate) { return _deviceToken; } }
    }

    /// <summary>Records the token returned by a successful registration.</summary>
    /// <remarks>
    /// A null or blank token is ignored rather than stored. Overwriting a working credential with
    /// nothing because one response happened to omit the field would take the agent offline until
    /// the next restart, and a backend that does not issue tokens is a deployment mismatch to be
    /// surfaced by the resulting 401s, not one to be silently absorbed here.
    /// </remarks>
    public void SetDeviceToken(string? token)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            return;
        }

        lock (_gate)
        {
            _deviceToken = token;
        }
    }
}
