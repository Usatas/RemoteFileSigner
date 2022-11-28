using System;
using System.IO;
using System.Threading;
using System.Windows;

using Microsoft.Win32;

using Remote_File_Signer.Shared;

using Remote_File_Signer_Client;

namespace Remote_File_Signer_Tester
{
    /// <summary>
    /// Interaktionslogik für MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        readonly MainWindowViewModel viewModel = new MainWindowViewModel();
        readonly Client client = new Client();
        static readonly CancellationTokenSource cancellation = new CancellationTokenSource();
        public MainWindow()
        {
            InitializeComponent();

            TBFilePath.DataContext = viewModel;
            TBStatus.DataContext = viewModel;

            AppDomain.CurrentDomain.ProcessExit += Exit;
        }

        private static void Exit(object sender, EventArgs e) => cancellation.Cancel();
        private void ButSelectFile_Click(object sender, RoutedEventArgs e)
        {
            try
            {

                var fileDialog = new OpenFileDialog
                {
                    Multiselect = false
                };

                fileDialog.ShowDialog();
                fileDialog.RestoreDirectory = true;
                fileDialog.CheckFileExists = true;
                fileDialog.CheckPathExists = true;
                viewModel.FilePath = fileDialog.FileName;

            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }

        }

        private async void ButSignFile_Click(object sender, RoutedEventArgs e)
        {
            viewModel.StatusMessage = "";
            if (!File.Exists(viewModel.FilePath))
            {
                viewModel.StatusMessage = "File not Found!";
                return;
            }
            try
            {
                char[] fileBody;

                // https://learn.microsoft.com/de-de/dotnet/api/system.io.streamreader.readasync?view=netframework-4.7.2
                using (var sr = new StreamReader(viewModel.FilePath))//, FileMode.Open, FileAccess.Read))
                {
                    fileBody = new char[sr.BaseStream.Length];

                    await sr.ReadAsync(fileBody, 0, fileBody.Length);


                }

                if (fileBody.Length > 0)
                {
                    // TEST
                    var file = Transfer.AddFrame(fileBody);

                    var (clearedData, valid) = Transfer.VerifyHeader(file);
                    Console.WriteLine($"old file length: {fileBody.Length} - cleared data length: {clearedData.Length}");
                    Console.WriteLine(valid ? "Creating Header successfull" : "Creating Header failed");

                    // TEST
                    var receivedData = await client.SendToServerAsync(file, cancellation.Token);

                    Console.WriteLine($"old file length: {fileBody.Length} - cleared data length: {receivedData.Length}");
                    Console.WriteLine(receivedData?.Length > 0 ? "Creating Header successfull" : "Creating Header failed");

                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failure sending file to sign: {ex}");
                viewModel.StatusMessage = "Unable to read file!";
                return;
            }

        }



    }


    public class MainWindowViewModel
    {
        private string filePath = "testFile.txt";

        public string FilePath
        {
            get => filePath;
            set => filePath = value;
        }

        private string statusMessage;

        public string StatusMessage
        {
            get => statusMessage;
            set => statusMessage = value;
        }

    }

}
