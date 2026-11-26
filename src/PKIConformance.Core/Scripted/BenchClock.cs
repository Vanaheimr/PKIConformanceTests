using System.Collections.Concurrent;

namespace PKIConformance.Core.Scripted;

/// <summary>
/// A clock of the bench for whatever takes a <see cref="TimeProvider"/>: its
/// time goes on only when something waits on it, by exactly as long as it
/// waits - and every wait is written down. A client told to wait 30 seconds
/// by a Retry-After waits no time at all, and the test reads the 30 seconds
/// off <see cref="Delays"/>.
/// </summary>
/// <remarks>
/// <para>
/// A timer fires at once (on the thread pool), after the clock was moved on
/// by its due time. Two waits at the same time move it by both, which is no
/// matter to a test that reads the delays asked for rather than the time.
/// </para>
/// <para>
/// What uses the system clock beside it - an HTTP client's own timeout, a
/// "Retry-After" date read against <see cref="DateTimeOffset.UtcNow"/> - is
/// not moved; a test that puts the clock far from the system's shows that.
/// </para>
/// </remarks>
public sealed class BenchClock : TimeProvider
{

    #region Data

    private readonly Lock      gate = new();
    private          DateTimeOffset now;

    #endregion

    #region Properties

    /// <summary>
    /// Every due time a timer was made with, in the order asked for.
    /// </summary>
    public ConcurrentQueue<TimeSpan> Delays { get; } = new();

    /// <summary>
    /// Whether a timer fires at once. Off, the clock stands still and timers
    /// fire only when <see cref="Advance"/> passes their time.
    /// </summary>
    public Boolean AutoAdvance { get; set; } = true;

    #endregion

    #region Constructor(s)

    /// <summary>
    /// A clock that starts at the given time - the system's, by default.
    /// </summary>
    public BenchClock(DateTimeOffset? Start = null)
    {
        now = Start ?? DateTimeOffset.UtcNow;
    }

    #endregion


    #region GetUtcNow() / Advance(By) / Set(To)

    /// <summary>
    /// How far the clock moves on at every reading while <see cref="AutoAdvance"/>
    /// is on: a millisecond, as time passes between two readings of a real
    /// clock. Without it a wait shorter than a millisecond - which .NET's
    /// Task.Delay returns from at once, without a timer - would leave the
    /// clock where it is, and whoever waits for it waiting forever.
    /// </summary>
    public TimeSpan AdvancePerReading { get; set; } = TimeSpan.FromMilliseconds(1);

    /// <inheritdoc/>
    public override DateTimeOffset GetUtcNow()
    {
        lock (gate)
        {
            if (AutoAdvance)
                now += AdvancePerReading;
            return now;
        }
    }

    /// <summary>
    /// Move the clock on, and fire what is due by then.
    /// </summary>
    public void Advance(TimeSpan By)
    {

        lock (gate)
            now += By;

        foreach (var timer in timers.Keys)
            timer.FireIfDue();

    }

    /// <summary>
    /// Set the clock - backwards as well.
    /// </summary>
    public void Set(DateTimeOffset To)
    {
        lock (gate)
            now = To;
    }

    #endregion


    #region CreateTimer(...)

    private readonly ConcurrentDictionary<BenchTimer, Byte> timers = new();

    /// <inheritdoc/>
    public override ITimer CreateTimer(TimerCallback  Callback,
                                       Object?        State,
                                       TimeSpan       DueTime,
                                       TimeSpan       Period)
    {

        var timer = new BenchTimer(this, Callback, State);
        timers[timer] = 0;
        timer.Change(DueTime, Period);
        return timer;

    }

    private sealed class BenchTimer(BenchClock      Clock,
                                    TimerCallback   Callback,
                                    Object?         State) : ITimer
    {

        private          Int32           generation;
        private          DateTimeOffset? due;
        private volatile Boolean         disposed;

        public Boolean Change(TimeSpan DueTime, TimeSpan Period)
        {

            if (disposed)
                return false;

            var mine = Interlocked.Increment(ref generation);

            if (DueTime == Timeout.InfiniteTimeSpan)
            {
                due = null;
                return true;
            }

            Clock.Delays.Enqueue(DueTime);

            if (Clock.AutoAdvance)
            {
                _ = Task.Run(() => {
                        if (disposed || Volatile.Read(ref generation) != mine)
                            return;
                        lock (Clock.gate)
                            Clock.now += DueTime;
                        Fire();
                    });
            }
            else
            {
                due = Clock.GetUtcNow() + DueTime;
                FireIfDue();
            }

            return true;

        }

        public void FireIfDue()
        {
            if (!disposed && due is DateTimeOffset at && Clock.GetUtcNow() >= at)
            {
                due = null;
                Fire();
            }
        }

        private void Fire()
        {
            if (!disposed)
                Callback(State);
        }

        public void Dispose()
        {
            disposed = true;
            Clock.timers.TryRemove(this, out _);
        }

        public ValueTask DisposeAsync()
        {
            Dispose();
            return ValueTask.CompletedTask;
        }

    }

    #endregion

}
