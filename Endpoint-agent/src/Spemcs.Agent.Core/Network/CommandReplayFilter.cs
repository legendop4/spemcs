using System;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Spemcs.Agent.Core.Network;

public enum CommandValidationStatus
{
    Accepted,
    MissingCommandId,
    Expired,
    FutureTimestamp,
    Replayed,
    InvalidContext
}

public sealed record CommandValidationOutcome(
    CommandValidationStatus Status,
    string? Details = null
);

public interface ICommandReplayFilter
{
    CommandValidationOutcome ValidateAndConsume(
        string commandId,
        string action,
        DateTimeOffset issuedAtUtc,
        Guid examId,
        Guid? sessionId = null,
        DateTimeOffset? currentUtc = null);
}

public sealed class CommandReplayFilter : ICommandReplayFilter
{
    private readonly IRollbackJournal _journal;
    private readonly ILogger<CommandReplayFilter> _logger;
    private readonly TimeSpan _maxSkew;

    public CommandReplayFilter(
        IRollbackJournal journal,
        ILogger<CommandReplayFilter>? logger = null,
        TimeSpan? maxSkew = null)
    {
        _journal = journal ?? throw new ArgumentNullException(nameof(journal));
        _logger = logger ?? NullLogger<CommandReplayFilter>.Instance;
        _maxSkew = maxSkew ?? TimeSpan.FromMinutes(5);
    }

    public CommandValidationOutcome ValidateAndConsume(
        string commandId,
        string action,
        DateTimeOffset issuedAtUtc,
        Guid examId,
        Guid? sessionId = null,
        DateTimeOffset? currentUtc = null)
    {
        if (string.IsNullOrWhiteSpace(commandId))
        {
            _logger.LogWarning("Command rejected: missing command_id");
            return new CommandValidationOutcome(CommandValidationStatus.MissingCommandId, "command_id is missing or empty.");
        }

        var now = currentUtc ?? DateTimeOffset.UtcNow;

        // Freshness check: reject stale/expired or future-dated commands
        if (now - issuedAtUtc > _maxSkew)
        {
            _logger.LogWarning("Command {CommandId} rejected: issued_at {IssuedAt} is older than allowed skew {Skew}",
                commandId, issuedAtUtc, _maxSkew);
            return new CommandValidationOutcome(CommandValidationStatus.Expired,
                $"Command is expired: issued at {issuedAtUtc:O}, current time is {now:O}.");
        }

        if (issuedAtUtc - now > _maxSkew)
        {
            _logger.LogWarning("Command {CommandId} rejected: issued_at {IssuedAt} is in the future relative to {Now}",
                commandId, issuedAtUtc, now);
            return new CommandValidationOutcome(CommandValidationStatus.FutureTimestamp,
                $"Command timestamp is too far in the future: issued at {issuedAtUtc:O}, current time is {now:O}.");
        }

        // Check duplicate / replay in durable journal
        if (_journal.IsCommandProcessed(commandId))
        {
            _logger.LogWarning("Command {CommandId} rejected: duplicate or replayed command.", commandId);
            return new CommandValidationOutcome(CommandValidationStatus.Replayed,
                $"Command '{commandId}' has already been processed and consumed.");
        }

        // Record in durable SQLite journal
        _journal.RecordProcessedCommand(
            commandId: commandId,
            action: action,
            examId: examId,
            sessionId: sessionId,
            expiresUtc: now.AddHours(24)
        );

        _logger.LogInformation("Command {CommandId} ({Action}) accepted and durably recorded.", commandId, action);
        return new CommandValidationOutcome(CommandValidationStatus.Accepted);
    }
}
