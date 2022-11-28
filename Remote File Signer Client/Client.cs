using System;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

using Remote_File_Signer.Shared;

namespace Remote_File_Signer_Client
{
    public class Client
    {
        private readonly Socket client;

        private static readonly string ServerHostName = "h2987990.stratoserver.net";
        private static readonly int ServerPort = 8433;
        private static readonly string ServerCertificateName = "h2987990.stratoserver.net"; // Server URL == Common Name 

        private static readonly string ClientCertificateFile = "client.pfx";
        private static readonly string ClientCertificatePassword = null;
        public const int bufferSize = 4096;

        public async Task<byte[]> SendToServerAsync(byte[] data, CancellationToken cancellationToken)
        {
            try
            {
                ////read from the store (must have a key there)
                //var store = new X509Store(StoreLocation.CurrentUser);
                //store.Open(OpenFlags.ReadOnly);
                //var clientCertificateCollection = store.Certificates.Find(X509FindType.FindBySubjectName, ClientCertificateName, false);

                //read from the file
                var clientCertificate = new X509Certificate2(ClientCertificateFile, ClientCertificatePassword);
                var clientCertificateCollection = new X509CertificateCollection(new X509Certificate[] { clientCertificate });

                using (var client = new TcpClient(ServerHostName, ServerPort))
                using (var sslStream = new SslStream(client.GetStream(), false, App_CertificateValidation))
                {
                    Console.WriteLine("Client connected.");

                    try
                    {
                        //X509Certificates.X509Certificate2Collection xc = new X509Certificates.X509Certificate2Collection();
                        //Stream.AuthenticateAsClient(hostname, xc, Security.Authentication.SslProtocols.Tls, false);
                        await sslStream.AuthenticateAsClientAsync(ServerCertificateName, clientCertificateCollection, SslProtocols.Tls12, false);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Authenticating as Server failed: {ex.Message}");
                        Console.WriteLine($"InnerException:{ex.InnerException}");
                        Console.WriteLine($"Source:{ex.Source}");
                        Console.WriteLine($"StackTrace:{ex.StackTrace}");
                        throw new Exception("Failed authenticating as server!", ex);
                    }

                    Console.WriteLine("SSL authentication completed.");
                    Console.WriteLine("SSL using local certificate {0}.", sslStream.LocalCertificate.Subject);
                    Console.WriteLine("SSL using remote certificate {0}.", sslStream.RemoteCertificate.Subject);


                    #region Send Username and Password

                    #endregion


                    #region send file
                    await SendAsync(sslStream, data, cancellationToken);
                    #endregion

                    #region receive file
                    var file = await ReceiveAsync(sslStream, cancellationToken);
                    //var outputMessage = "Hello from the client " + Process.GetCurrentProcess().Id.ToString() + ".";
                    //var outputBuffer = Encoding.UTF8.GetBytes(outputMessage);
                    #endregion

                    var (payload, valid) = Transfer.VerifyHeader(file);

                    if (!valid)
                    {
                        Console.WriteLine("Received Payload is invalid");

                    }
                    return payload;
                    //var inputMessage = Encoding.UTF8.GetString(inputBuffer, 0, inputBytes);
                    ////Console.WriteLine("Received: {0}", inputMessage);
                    //Console.WriteLine($"Received: {inputBytes} input bytes and a buffer with {inputBuffer.Length}");

                    //return (inputBuffer.Take(inputBytes).ToArray()); // ignore the unused buffer part
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"{ex}");
                Console.WriteLine("*** {0}\n*** {1}!", ex.GetType().Name, ex.Message);
            }

            Console.WriteLine();
            Console.WriteLine("Press any key to continue...");
            //Console.ReadKey();

            return Array.Empty<byte>();
        }

        internal async Task<byte[]> ReceiveAsync(SslStream sslStream, CancellationToken cancellationToken) => await Transfer.ReceiveAsync(sslStream, bufferSize, cancellationToken);
        internal async Task SendAsync(SslStream sslStream, byte[] data, CancellationToken cancellationToken) => await Transfer.SendAsync(sslStream, data, bufferSize, cancellationToken);
        /*

        public void ShowCertInfo()
        {

            try
            {

                //read from the file
                var clientCertificate = new X509Certificate2(ClientCertificateFile, ClientCertificatePassword);
                var clientCertificateCollection = new X509CertificateCollection(new X509Certificate[] { clientCertificate });

                X509Store store = new X509Store("MY", StoreLocation.CurrentUser);
                store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

                X509Certificate2Collection collection = (X509Certificate2Collection)store.Certificates;
                X509Certificate2Collection fcollection = (X509Certificate2Collection)collection.Find(X509FindType.FindByTimeValid, DateTime.Now, false);
                X509Certificate2Collection scollection = X509Certificate2UI.SelectFromCollection(fcollection, "Test Certificate Select", "Select a certificate from the following list to get information on that certificate", X509SelectionFlag.MultiSelection);
                Console.WriteLine("Number of certificates: {0}{1}", scollection.Count, Environment.NewLine);

                foreach (X509Certificate2 x509 in scollection)
                {
                    try
                    {
                        byte[] rawdata = x509.RawData;
                        Console.WriteLine("Content Type: {0}{1}", X509Certificate2.GetCertContentType(rawdata), Environment.NewLine);
                        Console.WriteLine("Friendly Name: {0}{1}", x509.FriendlyName, Environment.NewLine);
                        Console.WriteLine("Certificate Verified?: {0}{1}", x509.Verify(), Environment.NewLine);
                        Console.WriteLine("Simple Name: {0}{1}", x509.GetNameInfo(X509NameType.SimpleName, true), Environment.NewLine);
                        Console.WriteLine("Signature Algorithm: {0}{1}", x509.SignatureAlgorithm.FriendlyName, Environment.NewLine);
                        Console.WriteLine("Public Key: {0}{1}", x509.PublicKey.Key.ToXmlString(false), Environment.NewLine);
                        Console.WriteLine("Certificate Archived?: {0}{1}", x509.Archived, Environment.NewLine);
                        Console.WriteLine("Length of Raw Data: {0}{1}", x509.RawData.Length, Environment.NewLine);
                        X509Certificate2UI.DisplayCertificate(x509);
                        x509.Reset();
                    }
                    catch (CryptographicException)
                    {
                        Console.WriteLine("Information could not be written out for this certificate.");
                    }
                }
                store.Close();
            }
            catch (Exception ex)
            {
                Console.WriteLine("*** {0}\n*** {1}!", ex.GetType().Name, ex.Message);
            }

            Console.WriteLine();
            Console.WriteLine("Press any key to continue...");

        }*/

        private bool App_CertificateValidation(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            if (sslPolicyErrors == SslPolicyErrors.None)
            { return true; }
            if (sslPolicyErrors == SslPolicyErrors.RemoteCertificateChainErrors)
            { return true; } //we don't have a proper certificate tree
            else if (sslPolicyErrors == SslPolicyErrors.RemoteCertificateNameMismatch && certificate.Subject == "CN=" + ServerCertificateName)
            {
                return true;
            }
            Console.WriteLine("*** SSL Error: " + sslPolicyErrors.ToString());
            return false;
        }

        //public async void testSocket()
        //{
        //    //IPHostEntry ipHostInfo = await Dns.GetHostEntryAsync("host.contoso.com");
        //    //IPAddress ipAddress = ipHostInfo.AddressList[0];
        //    var ipAddress = IPAddress.Loopback;
        //    var ipEndPoint = new IPEndPoint(ipAddress, 11_000);



        //    client = new Socket(
        //                          ipEndPoint.AddressFamily,
        //                          SocketType.Stream,
        //                          ProtocolType.Tcp)
        //    ;
        //    {

        //        await client.ConnectAsync(ipEndPoint);

        //        try
        //        {

        //            // Send message.
        //            var message = "Hi friends 👋!<|EOM|>";
        //            var messageBytes = Encoding.UTF8.GetBytes(message);
        //            var socketArgs = new SocketAsyncEventArgs() { SocketFlags = SocketFlags.None };
        //            socketArgs.SetBuffer(messageBytes, 0, messageBytes.Length);
        //            socketArgs.Completed += HandleCompleted;
        //            var sendAsync = client.SendAsync(socketArgs);
        //            Console.WriteLine($"Socket client sent {(sendAsync ? "async" : "sync")} message: \"{message}\" ");

        //            // Receive ack.
        //            var buffer = new byte[1_024];
        //            socketArgs.SetBuffer(buffer, 0, buffer.Length);
        //            var recvAsync = client.ReceiveAsync(socketArgs);

        //            var response = Encoding.UTF8.GetString(buffer, 0, socketArgs.BytesTransferred);

        //            // Sample output:
        //            //     Socket client sent message: "Hi friends 👋!<|EOM|>"
        //            //     Socket client received acknowledgment: "<|ACK|>"
        //        }
        //        catch (Exception ex)
        //        {
        //            /*
        //             * SendAsync
        //            ArgumentException

        //            Die Buffer-Eigenschaft oder BufferList-Eigenschaft des e-Parameters muss auf gültige Puffer verweisen. Eine dieser Eigenschaften kann festgelegt werden, nicht jedoch beide gleichzeitig.
        //            InvalidOperationException

        //            Es wird bereits ein Socketvorgang mit dem im e-Parameter angegebenen SocketAsyncEventArgs-Objekt ausgeführt.
        //            NotSupportedException

        //            Für diese Methode ist Windows XP oder höher erforderlich.
        //            ObjectDisposedException

        //            Der Socket wurde geschlossen.
        //            SocketException

        //            Der Socket ist noch nicht verbunden oder wurde nicht über eine Accept()-AcceptAsync(SocketAsyncEventArgs)- oder BeginAccept-Methode abgerufen.

        //            */


        //            Console.WriteLine($"Message type:{ex.GetType()} Message:{ex.Message}");
        //        }


        //    }
        //}

        //private void HandleCompleted(object sender, SocketAsyncEventArgs e)
        //{
        //    var response = Encoding.UTF8.GetString(e.Buffer, 0, e.BytesTransferred);

        //    Console.WriteLine($"Socket client async completed! Buffer: \"{response}\" Socket error:\"{e.SocketError}\"");

        //    if (response == "<|ACK|>")
        //    {
        //        Console.WriteLine(
        //            $"Socket client received acknowledgment: \"{response}\"");
        //        client?.Shutdown(SocketShutdown.Both);
        //    }
        //}
    }
}
