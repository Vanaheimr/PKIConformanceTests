using System.Reflection;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.ACME;

using PKINode = cloud.charging.open.PKI.PKI;

namespace PKIConformance.Core;

/// <summary>
/// The cell of the interop matrix a test is - one of <see cref="InteropCells"/>.
/// </summary>
/// <remarks>
/// A test of several cases may name a cell for one of its arguments: the
/// cell whose <see cref="Argument"/> is among the case's arguments is taken,
/// otherwise the one without - "127.0.0.1" an address, a name a name.
/// </remarks>
/// <param name="Name">The cell, a constant of <see cref="InteropCells"/>.</param>
[AttributeUsage(AttributeTargets.Method, AllowMultiple = true)]
public sealed class CellAttribute(String Name) : Attribute
{

    /// <summary>The cell.</summary>
    public String   Name      { get; } = Name;

    /// <summary>The argument of a test case this cell is of, where the cases are of more than one.</summary>
    public String?  Argument  { get; init; }

}


/// <summary>
/// Which revisions of this family's two sides run - the PKI's and Hermod's
/// commits, as their builds stamped them into their assemblies.
/// </summary>
public static class Revisions
{

    /// <summary>"PKI ba8324a9": the PKI, as the server of interop A.</summary>
    public static String PKI
        => $"PKI {CommitOf(typeof(PKINode).Assembly)}";

    /// <summary>"Hermod 0a93a6fb": Hermod, as the client of interop B.</summary>
    public static String Hermod
        => $"Hermod {CommitOf(typeof(ACMEClient).Assembly)}";

    /// <summary>
    /// The commit an assembly was built from, as its Directory.Build.props
    /// stamped it - shortened as git shortens it.
    /// </summary>
    public static String CommitOf(Assembly Assembly)
    {

        var commit = Assembly.GetCustomAttributes<AssemblyMetadataAttribute>().
                              FirstOrDefault(metadata => metadata.Key == "GitCommit")?.Value ?? "unknown";

        return commit.Length > 8 && !commit.StartsWith("unknown")
                   ? commit[..8] + (commit.EndsWith("-dirty") ? "-dirty" : "")
                   : commit;

    }

}


/// <summary>
/// The declaration of a running test's cell, by its fixture's SetUp
/// (<see cref="InteropCells.Line"/>).
/// </summary>
public static class InteropMatrix
{

    /// <summary>
    /// Write the line of the running test's cell into its output: its
    /// <see cref="CellAttribute"/> - or its name, where it has none - and the
    /// finding or ToDo of its <c>[Property]</c>, if any.
    /// </summary>
    /// <param name="Matrix">The matrix, a constant of <see cref="InteropCells"/>.</param>
    /// <param name="Peer">The peer of other hands, with its version.</param>
    /// <param name="Against">This family's side and its commit: <see cref="Revisions"/>.</param>
    public static void Declare(String Matrix,
                               String Peer,
                               String Against)
    {

        var test       = TestContext.CurrentContext.Test;
        var method     = NUnit.Framework.Internal.TestExecutionContext.CurrentContext.CurrentTest.Method?.MethodInfo;
        var arguments  = test.Arguments.Select(argument => argument?.ToString()).ToHashSet();

        var cells      = method?.GetCustomAttributes<CellAttribute>().ToArray() ?? [];
        var cell       = cells.FirstOrDefault(candidate => candidate.Argument is not null && arguments.Contains(candidate.Argument))
                      ?? cells.FirstOrDefault(candidate => candidate.Argument is null);

        TestContext.Out.WriteLine(InteropCells.Line(Matrix,
                                                    Peer,
                                                    Against,
                                                    cell?.Name ?? test.MethodName ?? test.Name,
                                                    PropertyOf(method, "Finding"),
                                                    PropertyOf(method, "ToDo")));

    }

    private static String? PropertyOf(MethodInfo? Method, String Name)

        => Method?.GetCustomAttributes<PropertyAttribute>().
                   Concat(Method.DeclaringType?.GetCustomAttributes<PropertyAttribute>(inherit: true) ?? []).
                   SelectMany(property => property.Properties[Name].Cast<Object>()).
                   Select    (value    => value.ToString()).
                   FirstOrDefault();

}
