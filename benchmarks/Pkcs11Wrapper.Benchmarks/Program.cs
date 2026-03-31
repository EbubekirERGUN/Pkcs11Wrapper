using System.Linq;
using BenchmarkDotNet.Reports;
using BenchmarkDotNet.Running;

namespace Pkcs11Wrapper.Benchmarks;

internal static class Program
{
    private static void Main(string[] args)
    {
        Summary[] summaries = BenchmarkSwitcher.FromAssembly(typeof(Program).Assembly).Run(args).ToArray();
        BenchmarkSummaryWriter.Write(summaries);
    }
}
