using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Threading;
using DetectionApp.Classes;
using System.Runtime.InteropServices;
namespace DetectionApp
{
    public partial class MainWindow : Window
    {
        string FILE_PATH = "C:\\Windows\\System32\\ScanResult.txt";
        bool started = false;

        // Import functions from the agent dll

        [DllImport("DetectionAgentDLL.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int SendNewProcessToDriver(int Pid);

        [DllImport("DetectionAgentDLL.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int SendScanRequestToDriver();

        [DllImport("DetectionAgentDLL.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int UpdateDriverProcessList();

        [DllImport("DetectionAgentDLL.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int ShowScanResults();

        [DllImport("DetectionAgentDLL.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int StartAgent();

        [DllImport("DetectionAgentDLL.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int StopAgent();


        public MainWindow()
        {
            InitializeComponent();
            Btn.Click += Btn_Click;
        }

        private void Btn_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                Scan();
            }
            catch (DllNotFoundException)
            {
                MessageBox.Show("Failed to find DetectionAgentDLL.dll", "Error");
                return;
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "Error");
                return;
            }
        }

        private void Scan()
        {
            if (started == false && StartAgent() == 0)
            {
                MessageBox.Show("Failed to start agent", "Error");
                return;
            }
            started = true;

            if (UpdateDriverProcessList() == 0)
            {
                MessageBox.Show("Failed to update process list", "Error");
                return;
            }

            if (SendScanRequestToDriver() == 0)
            {
                MessageBox.Show("Failed to perform scan request", "Error");
                return;
            }

            if (FillLists() == 0)
            {
                MessageBox.Show("Failed to fill data in GUI", "Error");
                return;
            }

            MessageBox.Show("Finished scan", "Notification");
        }

        // Fill the ListViews using the external file
        private byte FillLists()
        {
            if (!File.Exists(FILE_PATH))
            {
                MessageBox.Show("Couldn't find external file. Was scan made?", "Error");
                return 0;
            }

            // Reset Lists
            this.IatList.Items.Clear();
            this.KiatList.Items.Clear();
            this.SsdtList.Items.Clear();
            this.IrpList.Items.Clear();
            this.IdtList.Items.Clear();

            string s = null;
            string[] arr = null;
            using (StreamReader sr = File.OpenText(FILE_PATH))
            {
                while((s = sr.ReadLine()) != null)
                {
                    if (s == null || !s.Contains('|'))
                    {
                        MessageBox.Show("External file content is invalid", "Error");
                        return 0;
                    }

                    arr = s.Split('|');
                    if (s.Substring(0, 4) == "IAT|")
                    {
                        this.IatList.Items.Add(new Iat
                        {
                            Name = arr[1],
                            Pid = arr[2],
                            Hooked = arr[3] == "1" ? "True" : "False"
                        });
                    }
                    else if (s.Substring(0, 5) == "KIAT|")
                    {
                        this.KiatList.Items.Add(new Kiat
                        {
                            Name = arr[1],
                            Hooked = arr[2] == "1" ? "True" : "False"
                        });
                    }
                    else if (s.Substring(0, 5) == "SSDT|")
                    {
                        SsdtList.Items.Add(new Ssdt
                        {
                            Id = arr[1],
                            Hooked = arr[2] == "1" ? "True" : "False",
                        });
                    }
                    else if (s.Substring(0, 4) == "IRP|")
                    {
                        IrpList.Items.Add(new Irp
                        {
                            Name = arr[1],
                            Hooked = arr[2] == "1" ? "True" : "False"
                        });
                    }
                    else if (s.Substring(0, 4) == "IDT|")
                    {
                        IdtList.Items.Add(new Idt
                        {
                            InterruptId = arr[1],
                            Hooked = arr[2] == "1" ? "True" : arr[2] == "-1" ? "Error" : "False"
                        });
                    }
                }
            }

            return 1;
        }
    }
}
