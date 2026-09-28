using Microsoft.Extensions.Logging;
using Spemcs.Agent.Core;

namespace Spemcs.Agent.Service;

public sealed record ExamActivationRequest(
    Guid ExamId,
    string ExamName,
    string? AllowedDomain = null,
    string? ApprovedBrowser = null
);

public interface IExamLifecycleCoordinator
{
    void RegisterHandler(
        Func<ExamActivationRequest, CancellationToken, Task<bool>> launchHandler,
        Func<CancellationToken, Task<bool>> stopHandler
    );

    Task<bool> LaunchExamAsync(ExamActivationRequest request, CancellationToken cancellationToken);
    Task<bool> StopExamAsync(CancellationToken cancellationToken);

    bool IsLaunchInProgress { get; }
    Guid? CurrentExamId { get; }
}

public sealed class ExamLifecycleCoordinator : IExamLifecycleCoordinator
{
    private readonly ILogger<ExamLifecycleCoordinator> _log;
    private Func<ExamActivationRequest, CancellationToken, Task<bool>>? _launchHandler;
    private Func<CancellationToken, Task<bool>>? _stopHandler;
    private readonly object _stateLock = new();

    private bool _launchInProgress;
    private Guid? _currentExamId;

    public bool IsLaunchInProgress
    {
        get { lock (_stateLock) { return _launchInProgress; } }
    }

    public Guid? CurrentExamId
    {
        get { lock (_stateLock) { return _currentExamId; } }
    }

    private readonly TaskCompletionSource _handlerRegistered = new(TaskCreationOptions.RunContinuationsAsynchronously);

    public ExamLifecycleCoordinator(ILogger<ExamLifecycleCoordinator> log)
    {
        _log = log;
    }

    public void RegisterHandler(
        Func<ExamActivationRequest, CancellationToken, Task<bool>> launchHandler,
        Func<CancellationToken, Task<bool>> stopHandler)
    {
        lock (_stateLock)
        {
            _launchHandler = launchHandler;
            _stopHandler = stopHandler;
            _handlerRegistered.TrySetResult();
        }
    }

    public async Task<bool> LaunchExamAsync(ExamActivationRequest request, CancellationToken cancellationToken)
    {
        lock (_stateLock)
        {
            // Idempotency: If launch is already in progress or exam is already launched for this ExamId, do not duplicate
            if (_launchInProgress && _currentExamId == request.ExamId)
            {
                _log.LogInformation("Exam launch already in progress for ExamId {ExamId}; ignoring duplicate request.", request.ExamId);
                return true;
            }

            _launchInProgress = true;
            _currentExamId = request.ExamId;
        }

        if (_launchHandler == null)
        {
            try
            {
                using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);
                await _handlerRegistered.Task.WaitAsync(linkedCts.Token).ConfigureAwait(false);
            }
            catch { }
        }

        if (_launchHandler == null)
        {
            _log.LogWarning("No launch handler registered in ExamLifecycleCoordinator; cannot launch exam {ExamId}.", request.ExamId);
            lock (_stateLock) { _launchInProgress = false; }
            return false;
        }

        try
        {
            var accepted = await _launchHandler(request, cancellationToken).ConfigureAwait(false);
            if (!accepted)
            {
                _log.LogWarning("Launch handler rejected exam activation for ExamId {ExamId}.", request.ExamId);
                lock (_stateLock)
                {
                    _launchInProgress = false;
                    _currentExamId = null;
                }
            }
            return accepted;
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Failed to launch exam {ExamId} via lifecycle handler.", request.ExamId);
            lock (_stateLock)
            {
                _launchInProgress = false;
                _currentExamId = null;
            }
            return false;
        }
    }

    public async Task<bool> StopExamAsync(CancellationToken cancellationToken)
    {
        lock (_stateLock)
        {
            _launchInProgress = false;
            _currentExamId = null;
        }

        if (_stopHandler == null)
        {
            try
            {
                using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);
                await _handlerRegistered.Task.WaitAsync(linkedCts.Token).ConfigureAwait(false);
            }
            catch { }
        }

        if (_stopHandler == null)
        {
            _log.LogWarning("No stop handler registered in ExamLifecycleCoordinator.");
            return false;
        }

        try
        {
            return await _stopHandler(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Failed to stop exam via lifecycle handler.");
            return false;
        }
    }
}
