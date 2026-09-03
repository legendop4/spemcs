using Spemcs.Agent.Core;
using Xunit;

namespace Spemcs.Agent.Tests;

public sealed class EventStoreTests
{
    [Fact]
    public void Event_delivery_transitions_and_retention_preserve_unresolved_events()
    {
        var root = Path.Combine(Path.GetTempPath(), "spemcs-events", Guid.NewGuid().ToString("N"));
        try
        {
            var store = new SqliteAgentStore(root);
            var pending = CreateEvent("pending");
            var retry = CreateEvent("retry");
            var uploaded = CreateEvent("uploaded");

            store.Enqueue(pending);
            store.Enqueue(retry);
            store.Enqueue(uploaded);

            var claimed = store.ClaimPendingEvents(10);
            Assert.Equal(3, claimed.Count);
            Assert.All(claimed, e => Assert.Equal(EventDeliveryStatus.Uploading, e.DeliveryStatus));

            store.MarkUploadFailed(retry.EventId, DateTimeOffset.UtcNow.AddMinutes(10));
            Assert.Single(store.GetEvents(EventDeliveryStatus.Failed));

            Assert.Empty(store.ClaimPendingEvents(10));
            Assert.Single(store.ClaimPendingEvents(10, DateTimeOffset.UtcNow.AddMinutes(11)));

            store.MarkUploaded(uploaded.EventId);
            Assert.Single(store.GetEvents(EventDeliveryStatus.Uploaded));

            Assert.Equal(1, store.PurgeUploaded(DateTimeOffset.UtcNow.AddMinutes(1)));
            Assert.Equal(2, store.GetEvents(EventDeliveryStatus.Uploading).Count);
            Assert.Empty(store.GetEvents(EventDeliveryStatus.Failed));
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, true);
        }
    }

    private static ViolationEvent CreateEvent(string name) => new(
        Guid.NewGuid(),
        "LAB-01",
        "R-1",
        "APPLICATION_OPENED",
        42,
        name,
        DateTimeOffset.UtcNow,
        $"C:\\{name}.exe",
        "test-rule");
}
