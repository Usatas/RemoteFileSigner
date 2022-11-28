using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Security;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Remote_File_Signer.Shared
{
    public static class Transfer
    {

        /// <summary>
        /// Adds UInt32 length at start and an SHA256 Hash at the end of the given file body. Length includes hash and Hash includes length!
        /// </summary>
        /// <param name="fileBody"></param>
        /// <returns></returns>
        public static byte[] AddFrame(char[] fileBody)
        {
            List<byte> result = new List<byte>();
            foreach (char c in fileBody)
            {
                result.AddRange(BitConverter.GetBytes(c));
            }
            return AddFrame(result.ToArray());
        }

        /// <summary>
        /// Adds UInt32 length at start and an SHA256 Hash at the end of the given file body. Length includes hash and Hash includes length!
        /// </summary>
        /// <param name="fileBody"></param>
        /// <returns></returns>
        public static byte[] AddFrame(byte[] fileBody)
        {
            List<byte> result = new List<byte>();
            using (SHA256 mySHA256 = SHA256.Create())
            {

                result.AddRange(fileBody);

                uint dlc = (uint)result.Count() + SizeOfSHA256; // add size of SHA256
                result.InsertRange(0, BitConverter.GetBytes(dlc));
                byte[] hash = mySHA256.ComputeHash(result.ToArray());
                result.AddRange(hash);

                result.Insert(0, StartByte); // Startbyte 1100 0011
                result.Add(EndByte); // Endbyte 0110 1001

                //#if DEBUG

                StringBuilder sbHash = new StringBuilder();
                foreach (byte c in hash)
                {
                    sbHash.Append($"{c:X2} ");
                }
                StringBuilder sbNewHash = new StringBuilder();

                Console.WriteLine($"DLC: \"{dlc}\"");
                Console.WriteLine($"Hash: \"{sbHash}");
                //#endif
            }
            return result.ToArray();
        }
        public static byte StartByte = 0xC3;
        public static byte EndByte = 0x69;
        public static uint SizeOfSHA256 = 32;

        /// <summary>
        /// Additional bytes to payload = Start/End byte + DLC (excluding hash because it is within dlc)
        /// </summary>
        public static uint SizeOfFrameOverhead = 2 + sizeof(uint);

        public static (byte[] cleanedData, bool valid) VerifyHeader(byte[] data)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }
            if (!(data.Length > (2 + SizeOfSHA256 + sizeof(uint)))) // start+end bytes + sha256 + dlc 
            {

                throw new ArgumentOutOfRangeException(nameof(data), $"Given array is to short! => \"{data.Length}\"");
            }
            if (data[0] != StartByte)
            {
                throw new FormatException($"Frame has invalid Startbyte! Expected: {StartByte} Actual: {data[0]}");
            }
            //if (data[0] != StartByte || data[data.Length - 1] != EndByte)
            //{
            //    throw new FormatException($"Frame has invalid Start/Endbyte! Expected: {StartByte}/{EndByte}  Actual: {data[0]}/{data[data.Length - 1]}");
            //}

            data = data.Skip(1).ToArray(); // remove StartByte 

            using (SHA256 mySHA256 = SHA256.Create())
            {
                uint oldDlc = BitConverter.ToUInt32(data, 0); // first 4 bytes

                if (data.Length < (oldDlc + 1 + sizeof(uint))) // including endbyte and dlc
                {
                    throw new FormatException($"Frame is shorter then dlc! Expected: {oldDlc + 1 + sizeof(uint)}  Actual: {data.Length}");
                }

                if (data[oldDlc + sizeof(uint)] != EndByte)
                {
                    throw new FormatException($"Frame has invalid Endbyte! Expected:{EndByte}  Actual: {data[oldDlc + sizeof(uint)]}");
                }
                data = data.Take((int)(oldDlc + sizeof(uint))).ToArray(); // remove EndByte 

                byte[] oldHash = data.Skip((int)(data.Length - SizeOfSHA256)).ToArray(); // get the last 64 bytes
                //uint newDlc = (uint)data.Length - sizeof(uint); // just ignore the 4 bytes of dlc
                byte[] newHash = mySHA256.ComputeHash(data, 0, (int)(data.Length - SizeOfSHA256)); // calc hash including dlc and excluding old hash

                //#if DEBUG

                StringBuilder sbOldHash = new StringBuilder();
                foreach (byte c in oldHash)
                {
                    sbOldHash.Append($"{c:X2} ");
                }
                StringBuilder sbNewHash = new StringBuilder();
                foreach (byte c in newHash)
                {
                    sbNewHash.Append($"{c:X2} ");
                }
                Console.WriteLine($"Old DLC: \"{oldDlc}\"");//, new DLC: \"{newDlc}\" DLC equals: {oldDlc == newDlc}");
                Console.WriteLine($"Old Hash: \"{sbOldHash}\"");
                Console.WriteLine($"New Hash: \"{sbNewHash}\"");
                Console.WriteLine($"Hash equals: {oldHash.SequenceEqual(newHash)}");
                //#endif

                bool valid = oldHash.SequenceEqual(newHash);
                byte[] cleanedData = data.Skip(sizeof(uint)).Take(data.Length - sizeof(uint) - oldHash.Length).ToArray();
                return (cleanedData, valid);
            }

        }




        /// <summary>
        /// Sends <paramref name="data"/> in segments of <paramref name="bufferSize"/>
        /// </summary>
        /// <param name="sslStream"></param>
        /// <param name="data"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static async Task SendAsync(SslStream sslStream, byte[] data, int bufferSize, CancellationToken cancellationToken) // TODO über cancellation Token nachdenken
        {

            if (sslStream is null) // TODO hier besser abfangen ob die Verbindung besteht
            {
                throw new ArgumentNullException(nameof(sslStream));
            }
            if (bufferSize <= SizeOfFrameOverhead + SizeOfSHA256)
            {
                throw new ArgumentOutOfRangeException(nameof(bufferSize), $"Buffersize is to small => must be greater then {SizeOfFrameOverhead + SizeOfSHA256} bytes!");
            }

            List<byte> bytesToSend = new List<byte>();
            bytesToSend.AddRange(data);

            double segments = Math.Ceiling((double)(data.Length / bufferSize));
            Console.WriteLine($"Send data ({bytesToSend.Count} bytes) in {segments} segments");


            //// DEBUGGING
            //StringBuilder sbSend = new StringBuilder();
            //foreach (byte c in bytesToSend)
            //{
            //    sbSend.Append($"{c:X2} ");
            //}
            //Console.WriteLine($"Sending: \"{sbSend}");



            int currentSegemnt = 0;
            while (bytesToSend.Count > 0)
            {
                Console.WriteLine($"Send segment {currentSegemnt}/{segments}");
                byte[] sendBuffer = bytesToSend.Take(bufferSize).ToArray();
                await sslStream.WriteAsync(sendBuffer, 0, sendBuffer.Length, cancellationToken);
                bytesToSend.RemoveRange(0, sendBuffer.Length);
                currentSegemnt++;
            }

        }


        /// <summary>
        /// Waits 
        /// </summary>
        /// <param name="sslStream"></param>
        /// <param name="bufferSize"></param>
        /// <returns>Received byte array</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        /// <exception cref="InvalidDataException"></exception>
        public static async Task<byte[]> ReceiveAsync(SslStream sslStream, int bufferSize, CancellationToken cancellationToken)
        {


            if (sslStream is null) // TODO hier besser abfangen ob die Verbindung besteht
            {
                throw new ArgumentNullException(nameof(sslStream));
            }
            if (bufferSize <= SizeOfFrameOverhead + SizeOfSHA256)
            {
                throw new ArgumentOutOfRangeException(nameof(bufferSize), $"Buffersize is to small => must be greater then {SizeOfFrameOverhead + SizeOfSHA256} bytes!");
            }

            {
                byte[] receivedBuffer = new byte[bufferSize];
                int receivedBytesLength = 0;
                uint dlc = 0;

                receivedBytesLength = await sslStream.ReadAsync(receivedBuffer, 0, receivedBuffer.Length);
                Console.WriteLine($"inputBytes length: {receivedBytesLength}");
                Console.WriteLine($"receivedBuffer?.Length > 0 : {receivedBuffer?.Length > 0}");
                if (receivedBuffer?.Length > 0) // got anything?
                {
                    Console.WriteLine($"receivedBuffer[0] == Transfer.StartByte: {receivedBuffer[0] == Transfer.StartByte}");
                }
                List<byte> receivedData = new List<byte>();
                if (receivedBytesLength > 0 && receivedBuffer?.Length > (1 + sizeof(uint)) && receivedBuffer[0] == Transfer.StartByte) // valid start of file?
                {
                    receivedData.AddRange(receivedBuffer);
                    dlc = BitConverter.ToUInt32(receivedBuffer, 1);
                    Console.WriteLine($"DLC: \"{dlc}\"");
                    Console.WriteLine($"Received bytes: \"{receivedData.Count}\"");

                    while (receivedBytesLength > 0 && receivedData.Count <= dlc && !cancellationToken.IsCancellationRequested) // try reading while bytes are received and dlc is unreached 
                    {
                        receivedBuffer = new byte[bufferSize];

                        receivedBytesLength = await sslStream.ReadAsync(receivedBuffer, 0, receivedBuffer.Length, cancellationToken);
                        Console.WriteLine($"inputBytes length: {receivedBytesLength}");
                        Console.WriteLine($"receivedBuffer?.Length > 0 : {receivedBuffer?.Length > 0}");
                        Console.WriteLine($"Received bytes: \"{receivedData.Count}\"");
                        if (receivedBytesLength > 0 && receivedBuffer?.Length > 0)
                        {

                            receivedData.AddRange(receivedBuffer);
                        }
                    }
                    Console.WriteLine($"Received bytes result: \"{receivedData.Count}\"");




                    //// DEBUGGING
                    //StringBuilder sbRecv = new StringBuilder();
                    //foreach (byte c in receivedData)
                    //{
                    //    sbRecv.Append($"{c:X2} ");
                    //}
                    //Console.WriteLine($"Received: \"{sbRecv}");


                    if (!(receivedData.Count >= dlc + Transfer.SizeOfFrameOverhead)) // got enough bytes? => count >= start + end + size of dlc
                    {
                        // Handle invalid Size of received Frames
                        // DONE!

                        throw new InvalidDataException($"Not enough data received! Got: {receivedData?.Count} bytes - expected at least: {dlc + Transfer.SizeOfFrameOverhead} bytes");
                    }

                }

                return receivedData.ToArray<byte>();
            }
        }
    }
}
