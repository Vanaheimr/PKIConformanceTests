using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace PKIConformance.Core.Scripted;

/// <summary>
/// The resolver of the server under test on a bench (PLAN.md, section 0.3): a
/// small DNS server of its own on 127.0.0.1 over UDP that answers from a zone
/// the test fills - TXT records for dns-01, CNAMEs, A and AAAA - as a
/// recursive resolver answers: a CNAME chain followed, NXDOMAIN for a name it
/// does not know. It keeps every question it was asked.
/// </summary>
/// <remarks>
/// <para>
/// Written here on a <see cref="UdpClient"/> with a wire codec of a few lines,
/// not on Hermod's DNS server: the server under test asks through Hermod's
/// <c>DNSClient</c>, and Hermod is not to answer itself.
/// </para>
/// <para>
/// A name can also be made to go unanswered (a timeout) or to fail
/// (SERVFAIL).
/// </para>
/// </remarks>
public sealed class ScriptedDNSServer : IAsyncDisposable
{

    #region Types

    /// <summary>The record types the server knows.</summary>
    public static class Types
    {
        public const UInt16 A      = 1;
        public const UInt16 CNAME  = 5;
        public const UInt16 TXT    = 16;
        public const UInt16 AAAA   = 28;
    }

    private sealed record Record(UInt16   Type,
                                 Byte[]   RData,
                                 String?  Target);

    #endregion

    #region Data

    private readonly UdpClient                                       udp;
    private readonly CancellationTokenSource                         stop   = new();
    private readonly Task                                            loop;
    private readonly ConcurrentDictionary<String, List<Record>>      zone   = new(StringComparer.Ordinal);

    #endregion

    #region Properties

    /// <summary>The UDP port on 127.0.0.1.</summary>
    public UInt16                                    Port       { get; }

    /// <summary>Every question, as (name as asked, type), in order.</summary>
    public ConcurrentQueue<(String Name, UInt16 Type)> Questions { get; } = new();

    /// <summary>Names never answered.</summary>
    public ConcurrentDictionary<String, Boolean>     Silent     { get; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Names answered with SERVFAIL.</summary>
    public ConcurrentDictionary<String, Boolean>     ServFail   { get; } = new(StringComparer.OrdinalIgnoreCase);

    #endregion

    #region Constructor(s)

    public ScriptedDNSServer()
    {

        udp   = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        Port  = (UInt16) ((IPEndPoint) udp.Client.LocalEndPoint!).Port;
        loop  = Task.Run(ReceiveLoop);

    }

    #endregion


    #region NewDNSClient()

    /// <summary>
    /// A DNSClient of Hermod that asks this server alone, without a cache -
    /// what the server under test resolves every name with on the bench.
    /// </summary>
    public org.GraphDefined.Vanaheimr.Hermod.DNS.DNSClient NewDNSClient()

        => new (org.GraphDefined.Vanaheimr.Hermod.IPv4Address.Localhost,
                org.GraphDefined.Vanaheimr.Hermod.IPPort.Parse(Port),
                QueryTimeout:   TimeSpan.FromSeconds(2),
                UseQueryCache:  false);

    #endregion

    #region AddTXT(Name, Strings) / AddCNAME(Name, Target) / AddA(Name, Address) / Clear(Name)

    private static String Key(String Name)
        => Name.TrimEnd('.').ToLowerInvariant();

    private void Add(String Name, Record Record)
        => zone.AddOrUpdate(Key(Name), _ => [ Record ], (_, records) => { lock (records) records.Add(Record); return records; });

    /// <summary>
    /// A TXT record of the name, of the given character-strings - one
    /// string, or a value split in several (RFC 1035, section 3.3.14).
    /// </summary>
    public void AddTXT(String           Name,
                       params String[]  Strings)
    {

        var rdata = new List<Byte>();

        foreach (var text in Strings)
        {
            var octets = Encoding.ASCII.GetBytes(text);
            if (octets.Length > 255)
                throw new ArgumentException("A character-string has 255 octets at most.", nameof(Strings));
            rdata.Add((Byte) octets.Length);
            rdata.AddRange(octets);
        }

        Add(Name, new Record(Types.TXT, [.. rdata], null));

    }

    /// <summary>
    /// A CNAME of the name.
    /// </summary>
    public void AddCNAME(String  Name,
                         String  Target)

        => Add(Name, new Record(Types.CNAME, EncodeName(Target), Key(Target)));

    /// <summary>
    /// An A or AAAA record of the name.
    /// </summary>
    public void AddAddress(String     Name,
                           IPAddress  Address)

        => Add(Name, new Record(Address.AddressFamily == AddressFamily.InterNetworkV6 ? Types.AAAA : Types.A, Address.GetAddressBytes(), null));

    /// <summary>
    /// A name known, without any record - NOERROR and no answer, not NXDOMAIN.
    /// </summary>
    public void AddEmpty(String Name)
        => zone.TryAdd(Key(Name), []);

    /// <summary>
    /// The name forgotten.
    /// </summary>
    public void Clear(String Name)
        => zone.TryRemove(Key(Name), out _);

    /// <summary>
    /// The questions for the name, of any type.
    /// </summary>
    public IReadOnlyList<(String Name, UInt16 Type)> QuestionsFor(String Name)
        => [.. Questions.Where(question => Key(question.Name) == Key(Name))];

    #endregion


    #region (private) ReceiveLoop() / Answer(Query)

    private async Task ReceiveLoop()
    {
        try
        {
            while (!stop.IsCancellationRequested)
            {

                var datagram = await udp.ReceiveAsync(stop.Token);

                Byte[]? answer;

                try
                {
                    answer = Answer(datagram.Buffer);
                }
                catch (Exception)
                {
                    answer = null;
                }

                if (answer is not null)
                    await udp.SendAsync(answer, datagram.RemoteEndPoint, stop.Token);

            }
        }
        catch (OperationCanceledException) { }
        catch (ObjectDisposedException)    { }
        catch (SocketException)            { }
    }

    private Byte[]? Answer(Byte[] Query)
    {

        if (Query.Length < 12)
            return null;

        var id       = BinaryPrimitives.ReadUInt16BigEndian(Query.AsSpan(0));
        var flags    = BinaryPrimitives.ReadUInt16BigEndian(Query.AsSpan(2));
        var qdcount  = BinaryPrimitives.ReadUInt16BigEndian(Query.AsSpan(4));

        if ((flags & 0x8000) != 0 || qdcount != 1)
            return null;

        var at       = 12;
        var name     = ReadName(Query, ref at);
        var qtype    = BinaryPrimitives.ReadUInt16BigEndian(Query.AsSpan(at));
        var question = Query.AsSpan(12, at + 4 - 12).ToArray();

        Questions.Enqueue((name, qtype));

        if (Silent.ContainsKey(name.TrimEnd('.')))
            return null;

        var answers  = new List<Byte[]>();
        var rcode    = 0;

        if (ServFail.ContainsKey(name.TrimEnd('.')))
            rcode = 2;

        else
        {

            var current = Key(name);
            var owner   = EncodeName(name);

            for (var hops = 0; hops < 8; hops++)
            {

                if (!zone.TryGetValue(current, out var records))
                {
                    rcode = 3;
                    break;
                }

                Record[] snapshot;
                lock (records)
                    snapshot = [.. records];

                var cname = snapshot.FirstOrDefault(record => record.Type == Types.CNAME);

                if (cname is not null && qtype != Types.CNAME)
                {
                    answers.Add(ResourceRecord(owner, cname));
                    owner   = cname.RData;
                    current = cname.Target!;
                    continue;
                }

                answers.AddRange(snapshot.Where(record => record.Type == qtype).Select(record => ResourceRecord(owner, record)));
                break;

            }

        }

        var response = new List<Byte>();

        response.AddRange([ (Byte) (id >> 8), (Byte) id ]);
        // QR, the opcode and RD of the query, AA, RA, and the RCODE.
        var answerFlags = (UInt16) (0x8000 | (flags & 0x7900) | 0x0400 | 0x0080 | rcode);
        response.AddRange([ (Byte) (answerFlags >> 8), (Byte) answerFlags ]);
        response.AddRange([ 0, 1, (Byte) (answers.Count >> 8), (Byte) answers.Count, 0, 0, 0, 0 ]);
        response.AddRange(question);

        foreach (var answer in answers)
            response.AddRange(answer);

        return [.. response];

    }

    private static Byte[] ResourceRecord(Byte[]  Owner,
                                         Record  Record)
    {

        var rr = new List<Byte>(Owner);

        rr.AddRange([ (Byte) (Record.Type >> 8), (Byte) Record.Type, 0, 1 ]);   // type, class IN
        rr.AddRange([ 0, 0, 0, 60 ]);                                            // TTL
        rr.AddRange([ (Byte) (Record.RData.Length >> 8), (Byte) Record.RData.Length ]);
        rr.AddRange(Record.RData);

        return [.. rr];

    }

    private static String ReadName(Byte[] Message, ref Int32 At)
    {

        var labels = new List<String>();

        while (true)
        {

            var length = Message[At++];

            if (length == 0)
                break;

            if ((length & 0xC0) != 0)
                throw new FormatException("A question is not compressed.");

            labels.Add(Encoding.ASCII.GetString(Message, At, length));
            At += length;

        }

        return String.Join('.', labels);

    }

    private static Byte[] EncodeName(String Name)
    {

        var octets = new List<Byte>();

        foreach (var label in Name.TrimEnd('.').Split('.', StringSplitOptions.RemoveEmptyEntries))
        {
            var bytes = Encoding.ASCII.GetBytes(label);
            octets.Add((Byte) bytes.Length);
            octets.AddRange(bytes);
        }

        octets.Add(0);

        return [.. octets];

    }

    #endregion


    #region DisposeAsync()

    public async ValueTask DisposeAsync()
    {

        await stop.CancelAsync();
        udp.Dispose();

        try
        {
            await loop.WaitAsync(TimeSpan.FromSeconds(2));
        }
        catch { /* the loop goes with the process */ }

        stop.Dispose();

    }

    #endregion

}
