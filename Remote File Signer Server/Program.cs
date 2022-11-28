using System.Security.Cryptography.X509Certificates;

namespace Remote_File_Signer_Server
{
    public enum ReturnCode
    {
        ServerAuthFaild,
        InvalidFrameSize,
        InvalidFrame,
        Successful,
        FailedHandleClient,
        FailedHandleSession,
        GeneralError
    }
    public class Program
    {

        private static readonly int ServerPort = 8433;

        //private static readonly string ServerCertificateName = "MyServer";
        private static readonly string ServerCertificateFile = "server.pfx";
        private static readonly string? ServerCertificatePassword = null;

        public const int bufferSize = 4096;
        private static readonly CancellationTokenSource cancellation = new CancellationTokenSource();
        static async Task Main(string[] args)
        {
            try
            {
                ////read from the store (must have a key there)
                //var store = new X509Store(StoreLocation.CurrentUser);
                //store.Open(OpenFlags.ReadOnly);
                //var serverCertificateCollection = store.Certificates.Find(X509FindType.FindBySubjectName, ServerCertificateName, false);
                //var serverCertificate = serverCertificateCollection[0];

                //read from the file
                var serverCertificate = new X509Certificate2(ServerCertificateFile, ServerCertificatePassword);

                var server = new Server(serverCertificate, ServerPort, bufferSize);

                AppDomain.CurrentDomain.ProcessExit += Exit;

                await server.StartAsync(cancellation.Token);
            }
            catch (Exception ex)
            {
                Console.WriteLine("*** {0}\n*** {1}!", ex.GetType().Name, ex.Message);
                Console.WriteLine($"\n\n\n{ex}\n\n\n--------");
            }

            Console.WriteLine();
            Console.WriteLine("Server closed! Press any key to continue...");
            Console.ReadKey();
        }

        private static void Exit(object? sender, EventArgs e) => cancellation.Cancel();
    }
}