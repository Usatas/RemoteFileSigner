using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

using Remote_File_Signer.Shared;

namespace Remote_File_Signer_Server
{
    internal class Server
    {
        private readonly X509Certificate2 serverCertificate;
        private readonly int serverPort;
        private readonly int bufferSize;
        private readonly List<TcpClient> ClientList = new List<TcpClient>();

        public Server(X509Certificate2 serverCertificate, int serverPort, int bufferSize)
        {
            if (serverCertificate is null)
            {
                throw new ArgumentNullException((nameof(serverCertificate)));
            }
            this.serverCertificate = serverCertificate;

            this.serverPort = serverPort;
            this.bufferSize = bufferSize;
        }

        internal async Task StartAsync(CancellationToken cancellationToken)
        {
            Exception exTemp = null;
            var listener = new TcpListener(IPAddress.Any, serverPort); // can throw Exceptions eg. port number is invalid - handled in Remote_File_Signer.Program Main!
            try
            {

                // can throw Exceptions eg. port number is invalid - handled in Remote_File_Signer.Program Main!
                listener.Start();

                Console.WriteLine("Started listening.");

                while (true && !cancellationToken.IsCancellationRequested)
                {
                    Console.WriteLine();
                    Console.WriteLine("Waiting for a client to connect...");

                    try
                    {

                        var client = await listener.AcceptTcpClientAsync();
                        ClientList.Add(client);
                        _ = HandleCLientAsync(client, cancellationToken).ConfigureAwait(false);


                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Failed handling client: {ex}");
                    }

                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failure within listener: {ex}");
                exTemp = ex;
            }
            finally
            {
                listener.Stop();
            }
            if (exTemp != null)
            {
                throw exTemp;
            }


        }


        private async Task<ReturnCode> HandleCLientAsync(TcpClient client, CancellationToken cancellationToken)
        {
            var returnCode = ReturnCode.GeneralError;

            try
            {

                using (var sslStream = new SslStream(client.GetStream(), false, App_CertificateValidation))
                {
                    Console.WriteLine("Accepted client " + client.Client.RemoteEndPoint?.ToString() ?? "NULL");

                    try
                    {

                        // SslProtocols.None
                        // Ermöglicht dem Betriebssystem, das am besten geeignete Protokoll auszuwählen und unsichere Protokolle zu blockieren.
                        // Sofern in Ihrer Anwendung kein bestimmter Grund besteht, dies nicht zu tun, sollten Sie dieses Feld verwenden.
                        await sslStream.AuthenticateAsServerAsync(serverCertificate, true, SslProtocols.Tls12, false); // TODO Hier noch das Protocoll ändern
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Authenticating as Server failed: {ex.Message}");
                        Console.WriteLine($"InnerException:{ex.InnerException}");
                        Console.WriteLine($"Source:{ex.Source}");
                        Console.WriteLine($"StackTrace:{ex.StackTrace}");
                        returnCode = ReturnCode.ServerAuthFaild;
                        throw new Exception("Failed authenticating as server!", ex);
                    }
                    Console.WriteLine("SSL authentication completed.");
                    Console.WriteLine("SSL using local certificate {0}.", sslStream.LocalCertificate?.Subject);
                    Console.WriteLine("SSL using remote certificate {0}.", sslStream.RemoteCertificate?.Subject);

                    //var outputMessage = "Hello from the server.";
                    //var outputBuffer = Encoding.UTF8.GetBytes(outputMessage);
                    //sslStream.Write(outputBuffer);
                    //Console.WriteLine("Sent: {0}", outputMessage);

                    #region Read login and load cert from db
                    // TODO Implement: Read login and load cert from db!!!

                    #endregion

                    #region Read and sign file
                    {
                        var receivedData = Array.Empty<byte>();
                        try
                        {

                            receivedData = await ReceiveAsync(sslStream, cancellationToken);
                        }
                        catch (InvalidDataException ex)
                        {
                            returnCode = ReturnCode.InvalidFrameSize;
                            throw ex;
                        }

                        // Size matches => check form and hash
                        var (payload, validFrame) = Transfer.VerifyHeader(receivedData.ToArray());

                        if (!validFrame)
                        {
                            // Handle invalid Frame / hash
                            // DONE!

                            returnCode = ReturnCode.InvalidFrame;
                            throw new InvalidDataException("Received data was in invalid format / SHA256 hash didn't match!");
                        }

                        Console.WriteLine($"inputBytes length: {receivedData.Length} - cleared data length: {payload.Length}");
                        Console.WriteLine(validFrame ? "Creating Header successful" : "Creating Header failed");

                        // TODO Sign file

                        // TODO Build Frame and send sign back
                        #region DIES IST NUR EIN TEST
                        if (payload?.Length > 0)
                        {
                            var completeFrame = Transfer.AddFrame(payload.ToArray());
                            await SendAsync(sslStream, completeFrame, cancellationToken);
                        }
                        else
                        {
                            Console.WriteLine("Nothing received => nothing to send back!");
                            var nothing = Transfer.AddFrame("Nothing received!".ToCharArray());

                            await SendAsync(sslStream, nothing, cancellationToken);

                        }
                        #endregion DIES IST NUR EIN TEST
                        // Happy successful - DONE!
                        // TODO forget client signing certificate from db, login, file,  ..... 

                        returnCode = ReturnCode.Successful;

                    }


                    #endregion Read and sign file
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed handle session of client: {ex}");
                returnCode = ReturnCode.FailedHandleSession;
            }

            finally
            {
                client.Close();
                var clientRemoved = ClientList.Remove(client);
                Console.WriteLine($"Client was removed from list: {clientRemoved}");
                client.Dispose();
            }

            return returnCode;
        }

        private async Task<byte[]> ReceiveAsync(SslStream sslStream, CancellationToken cancellationToken) => await Transfer.ReceiveAsync(sslStream, bufferSize, cancellationToken);


        private async Task SendAsync(SslStream sslStream, byte[] data, CancellationToken cancellationToken) => await Transfer.SendAsync(sslStream, data, bufferSize, cancellationToken);

        private static bool App_CertificateValidation(object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors sslPolicyErrors) // TODO App_CertificateValidation noch ausprogrammieren
        {
            if (sslPolicyErrors == SslPolicyErrors.None)
            { return true; }
            if (sslPolicyErrors == SslPolicyErrors.RemoteCertificateChainErrors)
            { return true; } //we don't have a proper certificate tree
            Console.WriteLine("*** SSL Error: " + sslPolicyErrors.ToString());
            return false;
        }

    }
}