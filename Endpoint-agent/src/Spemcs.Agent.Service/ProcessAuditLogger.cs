using Microsoft.Extensions.Logging;
using Spemcs.Agent.Core;

namespace Spemcs.Agent.Service;

public sealed class ProcessAuditLogger : IProcessAuditSink
{
    private readonly ILogger _log;
    public ProcessAuditLogger(ILogger log) { _log = log; }
    public void Record(string action, ProcessInfo process, ClassificationResult classification) =>
        _log.LogInformation("Pre-compliance process decision: pid={Pid} name={Name} path={Path} classification={Classification} rule={Rule} action={Action} reason={Reason}",
            process.ProcessId, process.Name, process.ExecutablePath, classification.Classification, classification.Rule, action, classification.Reason);
}
