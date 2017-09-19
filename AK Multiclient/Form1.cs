using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace AK_Multiclient
{
    public partial class Form1 : Form
    {
        public class Win32API
        {
            [DllImport("ntdll.dll")]
            public static extern int NtQueryObject(IntPtr ObjectHandle, int
                ObjectInformationClass, IntPtr ObjectInformation, int ObjectInformationLength,
                ref int returnLength);

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern uint QueryDosDevice(string lpDeviceName, StringBuilder lpTargetPath, int ucchMax);

            [DllImport("ntdll.dll")]
            public static extern uint NtQuerySystemInformation(int
                SystemInformationClass, IntPtr SystemInformation, int SystemInformationLength,
                ref int returnLength);

            [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern IntPtr OpenMutex(UInt32 desiredAccess, bool inheritHandle, string name);

            [DllImport("kernel32.dll")]
            public static extern IntPtr OpenProcess(ProcessAccessFlags dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, int dwProcessId);

            [DllImport("kernel32.dll")]
            public static extern int CloseHandle(IntPtr hObject);

            [DllImport("kernel32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool DuplicateHandle(IntPtr hSourceProcessHandle,
               ushort hSourceHandle, IntPtr hTargetProcessHandle, out IntPtr lpTargetHandle,
               uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwOptions);

            [DllImport("kernel32.dll")]
            public static extern IntPtr GetCurrentProcess();

            public enum ObjectInformationClass : int
            {
                ObjectBasicInformation = 0,
                ObjectNameInformation = 1,
                ObjectTypeInformation = 2,
                ObjectAllTypesInformation = 3,
                ObjectHandleInformation = 4
            }

            [Flags]
            public enum ProcessAccessFlags : uint
            {
                All = 0x001F0FFF,
                Terminate = 0x00000001,
                CreateThread = 0x00000002,
                VMOperation = 0x00000008,
                VMRead = 0x00000010,
                VMWrite = 0x00000020,
                DupHandle = 0x00000040,
                SetInformation = 0x00000200,
                QueryInformation = 0x00000400,
                Synchronize = 0x00100000
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct OBJECT_BASIC_INFORMATION
            { // Information Class 0
                public int Attributes;
                public int GrantedAccess;
                public int HandleCount;
                public int PointerCount;
                public int PagedPoolUsage;
                public int NonPagedPoolUsage;
                public int Reserved1;
                public int Reserved2;
                public int Reserved3;
                public int NameInformationLength;
                public int TypeInformationLength;
                public int SecurityDescriptorLength;
                public System.Runtime.InteropServices.ComTypes.FILETIME CreateTime;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct OBJECT_TYPE_INFORMATION
            { // Information Class 2
                public UNICODE_STRING Name;
                public int ObjectCount;
                public int HandleCount;
                public int Reserved1;
                public int Reserved2;
                public int Reserved3;
                public int Reserved4;
                public int PeakObjectCount;
                public int PeakHandleCount;
                public int Reserved5;
                public int Reserved6;
                public int Reserved7;
                public int Reserved8;
                public int InvalidAttributes;
                public GENERIC_MAPPING GenericMapping;
                public int ValidAccess;
                public byte Unknown;
                public byte MaintainHandleDatabase;
                public int PoolType;
                public int PagedPoolUsage;
                public int NonPagedPoolUsage;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct OBJECT_NAME_INFORMATION
            { // Information Class 1
                public UNICODE_STRING Name;
            }

            [StructLayout(LayoutKind.Sequential, Pack = 1)]
            public struct UNICODE_STRING
            {
                public ushort Length;
                public ushort MaximumLength;
                public IntPtr Buffer;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct GENERIC_MAPPING
            {
                public int GenericRead;
                public int GenericWrite;
                public int GenericExecute;
                public int GenericAll;
            }

            [StructLayout(LayoutKind.Sequential, Pack = 1)]
            public struct SYSTEM_HANDLE_INFORMATION
            { // Information Class 16
                public int ProcessID;
                public byte ObjectTypeNumber;
                public byte Flags; // 0x01 = PROTECT_FROM_CLOSE, 0x02 = INHERIT
                public ushort Handle;
                public int Object_Pointer;
                public UInt32 GrantedAccess;
            }

            public const int MAX_PATH = 260;
            public const uint STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;
            public const int DUPLICATE_SAME_ACCESS = 0x2;
            public const int DUPLICATE_CLOSE_SOURCE = 0x1;
        }
        public class Win32Processes
        {
            const int CNST_SYSTEM_HANDLE_INFORMATION = 16;
            const uint STATUS_INFO_LENGTH_MISMATCH = 0xc0000004;

            public static string getObjectTypeName(Win32API.SYSTEM_HANDLE_INFORMATION shHandle, Process process)
            {
                IntPtr m_ipProcessHwnd = Win32API.OpenProcess(Win32API.ProcessAccessFlags.All, false, process.Id);
                IntPtr ipHandle = IntPtr.Zero;
                var objBasic = new Win32API.OBJECT_BASIC_INFORMATION();
                IntPtr ipBasic = IntPtr.Zero;
                var objObjectType = new Win32API.OBJECT_TYPE_INFORMATION();
                IntPtr ipObjectType = IntPtr.Zero;
                IntPtr ipObjectName = IntPtr.Zero;
                string strObjectTypeName = "";
                int nLength = 0;
                int nReturn = 0;
                IntPtr ipTemp = IntPtr.Zero;

                if (!Win32API.DuplicateHandle(m_ipProcessHwnd, shHandle.Handle,
                                              Win32API.GetCurrentProcess(), out ipHandle,
                                              0, false, Win32API.DUPLICATE_SAME_ACCESS))
                    return null;

                ipBasic = Marshal.AllocHGlobal(Marshal.SizeOf(objBasic));
                Win32API.NtQueryObject(ipHandle, (int)Win32API.ObjectInformationClass.ObjectBasicInformation,
                                       ipBasic, Marshal.SizeOf(objBasic), ref nLength);
                objBasic = (Win32API.OBJECT_BASIC_INFORMATION)Marshal.PtrToStructure(ipBasic, objBasic.GetType());
                Marshal.FreeHGlobal(ipBasic);

                ipObjectType = Marshal.AllocHGlobal(objBasic.TypeInformationLength);
                nLength = objBasic.TypeInformationLength;
                while ((uint)(nReturn = Win32API.NtQueryObject(
                    ipHandle, (int)Win32API.ObjectInformationClass.ObjectTypeInformation, ipObjectType,
                      nLength, ref nLength)) ==
                    Win32API.STATUS_INFO_LENGTH_MISMATCH)
                {
                    Marshal.FreeHGlobal(ipObjectType);
                    ipObjectType = Marshal.AllocHGlobal(nLength);
                }

                objObjectType = (Win32API.OBJECT_TYPE_INFORMATION)Marshal.PtrToStructure(ipObjectType, objObjectType.GetType());
                if (Is64Bits())
                {
                    ipTemp = new IntPtr(Convert.ToInt64(objObjectType.Name.Buffer.ToString(), 10) >> 32);
                }
                else
                {
                    ipTemp = objObjectType.Name.Buffer;
                }

                strObjectTypeName = Marshal.PtrToStringUni(ipTemp, objObjectType.Name.Length >> 1);
                Marshal.FreeHGlobal(ipObjectType);
                return strObjectTypeName;
            }


            public static string getObjectName(Win32API.SYSTEM_HANDLE_INFORMATION shHandle, Process process)
            {
                IntPtr m_ipProcessHwnd = Win32API.OpenProcess(Win32API.ProcessAccessFlags.All, false, process.Id);
                IntPtr ipHandle = IntPtr.Zero;
                var objBasic = new Win32API.OBJECT_BASIC_INFORMATION();
                IntPtr ipBasic = IntPtr.Zero;
                IntPtr ipObjectType = IntPtr.Zero;
                var objObjectName = new Win32API.OBJECT_NAME_INFORMATION();
                IntPtr ipObjectName = IntPtr.Zero;
                string strObjectName = "";
                int nLength = 0;
                int nReturn = 0;
                IntPtr ipTemp = IntPtr.Zero;

                if (!Win32API.DuplicateHandle(m_ipProcessHwnd, shHandle.Handle, Win32API.GetCurrentProcess(),
                                              out ipHandle, 0, false, Win32API.DUPLICATE_SAME_ACCESS))
                    return null;

                ipBasic = Marshal.AllocHGlobal(Marshal.SizeOf(objBasic));
                Win32API.NtQueryObject(ipHandle, (int)Win32API.ObjectInformationClass.ObjectBasicInformation,
                                       ipBasic, Marshal.SizeOf(objBasic), ref nLength);
                objBasic = (Win32API.OBJECT_BASIC_INFORMATION)Marshal.PtrToStructure(ipBasic, objBasic.GetType());
                Marshal.FreeHGlobal(ipBasic);


                nLength = objBasic.NameInformationLength;

                ipObjectName = Marshal.AllocHGlobal(nLength);
                while ((uint)(nReturn = Win32API.NtQueryObject(
                         ipHandle, (int)Win32API.ObjectInformationClass.ObjectNameInformation,
                         ipObjectName, nLength, ref nLength))
                       == Win32API.STATUS_INFO_LENGTH_MISMATCH)
                {
                    Marshal.FreeHGlobal(ipObjectName);
                    ipObjectName = Marshal.AllocHGlobal(nLength);
                }
                objObjectName = (Win32API.OBJECT_NAME_INFORMATION)Marshal.PtrToStructure(ipObjectName, objObjectName.GetType());

                if (Is64Bits())
                {
                    ipTemp = new IntPtr(Convert.ToInt64(objObjectName.Name.Buffer.ToString(), 10) >> 32);
                }
                else
                {
                    ipTemp = objObjectName.Name.Buffer;
                }

                if (ipTemp != IntPtr.Zero)
                {

                    byte[] baTemp2 = new byte[nLength];
                    try
                    {
                        Marshal.Copy(ipTemp, baTemp2, 0, nLength);

                        strObjectName = Marshal.PtrToStringUni(Is64Bits() ?
                                                               new IntPtr(ipTemp.ToInt64()) :
                                                               new IntPtr(ipTemp.ToInt32()));
                        return strObjectName;
                    }
                    catch (AccessViolationException)
                    {
                        return null;
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(ipObjectName);
                        Win32API.CloseHandle(ipHandle);
                    }
                }
                return null;
            }

            public static List<Win32API.SYSTEM_HANDLE_INFORMATION>
            GetHandles(Process process = null, string IN_strObjectTypeName = null, string IN_strObjectName = null)
            {
                uint nStatus;
                int nHandleInfoSize = 0x10000;
                IntPtr ipHandlePointer = Marshal.AllocHGlobal(nHandleInfoSize);
                int nLength = 0;
                IntPtr ipHandle = IntPtr.Zero;

                while ((nStatus = Win32API.NtQuerySystemInformation(CNST_SYSTEM_HANDLE_INFORMATION, ipHandlePointer,
                                                                    nHandleInfoSize, ref nLength)) ==
                        STATUS_INFO_LENGTH_MISMATCH)
                {
                    nHandleInfoSize = nLength;
                    Marshal.FreeHGlobal(ipHandlePointer);
                    ipHandlePointer = Marshal.AllocHGlobal(nLength);
                }

                byte[] baTemp = new byte[nLength];
                Marshal.Copy(ipHandlePointer, baTemp, 0, nLength);

                long lHandleCount = 0;
                if (Is64Bits())
                {
                    lHandleCount = Marshal.ReadInt64(ipHandlePointer);
                    ipHandle = new IntPtr(ipHandlePointer.ToInt64() + 8);
                }
                else
                {
                    lHandleCount = Marshal.ReadInt32(ipHandlePointer);
                    ipHandle = new IntPtr(ipHandlePointer.ToInt32() + 4);
                }

                Win32API.SYSTEM_HANDLE_INFORMATION shHandle;
                List<Win32API.SYSTEM_HANDLE_INFORMATION> lstHandles = new List<Win32API.SYSTEM_HANDLE_INFORMATION>();

                for (long lIndex = 0; lIndex < lHandleCount; lIndex++)
                {
                    shHandle = new Win32API.SYSTEM_HANDLE_INFORMATION();
                    if (Is64Bits())
                    {
                        shHandle = (Win32API.SYSTEM_HANDLE_INFORMATION)Marshal.PtrToStructure(ipHandle, shHandle.GetType());
                        ipHandle = new IntPtr(ipHandle.ToInt64() + Marshal.SizeOf(shHandle) + 8);
                    }
                    else
                    {
                        ipHandle = new IntPtr(ipHandle.ToInt64() + Marshal.SizeOf(shHandle));
                        shHandle = (Win32API.SYSTEM_HANDLE_INFORMATION)Marshal.PtrToStructure(ipHandle, shHandle.GetType());
                    }

                    if (process != null)
                    {
                        if (shHandle.ProcessID != process.Id) continue;
                    }

                    string strObjectTypeName = "";
                    if (IN_strObjectTypeName != null)
                    {
                        strObjectTypeName = getObjectTypeName(shHandle, Process.GetProcessById(shHandle.ProcessID));
                        if (strObjectTypeName != IN_strObjectTypeName) continue;
                    }

                    string strObjectName = "";
                    if (IN_strObjectName != null)
                    {
                        strObjectName = getObjectName(shHandle, Process.GetProcessById(shHandle.ProcessID));
                        if (strObjectName != IN_strObjectName) continue;
                    }

                    string strObjectTypeName2 = getObjectTypeName(shHandle, Process.GetProcessById(shHandle.ProcessID));
                    string strObjectName2 = getObjectName(shHandle, Process.GetProcessById(shHandle.ProcessID));
                    Console.WriteLine("{0}   {1}   {2}", shHandle.ProcessID, strObjectTypeName2, strObjectName2);

                    lstHandles.Add(shHandle);
                }
                return lstHandles;
            }

            public static bool Is64Bits()
            {
                return Marshal.SizeOf(typeof(IntPtr)) == 8 ? true : false;
            }
        }
        public static bool IsAdministrator()
        {
            var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        // DONT FORGET TO ADD CHECK IF ADMINISTRATOR
        // IF NOT, TURN THIS SHIT OFF
        // LELELELELELELELELLELELELELELELELELLELELEL

        bool _started = false;

        public Form1()
        {
            InitializeComponent();
        }

        private void listBox1_SelectedIndexChanged(object sender, EventArgs e)
        {

        }

        private void Form1_Load(object sender, EventArgs e)
        {
            backgroundWorker1.RunWorkerAsync();
        }

        private void timer1_Tick(object sender, EventArgs e)
        {

        }

        private bool ProcessExists(int id)
        {
            return Process.GetProcesses().Any(x => x.Id == id);
        }

        private void button1_Click(object sender, EventArgs e)
        {
            if (_started == false)
            {
                _started = true;
                // start
                button1.Text = "Stop!";
            } else
            {
                _started = false;
                // stop;
                button1.Text = "Start!";
            }
        }

        string determineSession()
        {
            String foundSession;
            Process p = Process.GetProcessesByName("game.bin")[0];

            for(int i = 0; i < 11; i++) // you can make it check for a million session ids, but its probably not gonna be more than 10 xd
            {
                var handles = Win32Processes.GetHandles(p, "Directory", "\\Sessions\\" + i +"\\BaseNamedObjects");
                if (handles.Count > 0)
                {
                    foundSession = "\\Sessions\\" + i + "\\BaseNamedObjects\\";
                    return foundSession;
                }
            }

            return "n/a";
        }

        private void backgroundWorker1_DoWork(object sender, DoWorkEventArgs e)
        {
            // IF THIS DOESNT WORK FOR YOU THEN THIS IS THE PROBLEM
            // var handles = Win32Processes.GetHandles(p, "Mutant", "\\Sessions\\4\\BaseNamedObjects\\" + MutexToRemove);
            // SEE WHERE IT SAYS 4, THIS IS NOT MATCHING THE NUMBER ON YOUR COMPUTER
            // YOU CAN FIND THIS NUMBER USING PROCESS EXPLORER, CHOOSING GAME.BIN, CLICKING CTRL+H AND SCROLLING DOWN A BIT

            // TODO: AUTOMAGICALLY FETCH THE CORRECT SESSION NUMBER XD
            // UPDATE: USE FUNCTION 'determineSession' to automagically get the right string to work with

            String MutexToRemove = "FFClientTag";
            Process[] activeP;


            while (_started == true)
            {
                activeP = Process.GetProcessesByName("game.bin");

                foreach (Process p in activeP)
                {
                    var handles = Win32Processes.GetHandles(p, "Mutant", "\\Sessions\\4\\BaseNamedObjects\\" + MutexToRemove);
                    if (handles.Count < 1)
                    {
                        // ignore
                        // SIMPLY IGNORE OUR PROBLEMS
                    } else
                    {
                        foreach (var handle in handles)
                        {
                            try
                            {
                                IntPtr ipHandle = IntPtr.Zero;
                                if (!Win32API.DuplicateHandle(Process.GetProcessById(handle.ProcessID).Handle, handle.Handle, Win32API.GetCurrentProcess(), out ipHandle, 0, false, Win32API.DUPLICATE_CLOSE_SOURCE))
                                {
                                    Console.WriteLine("DuplicateHandle() failed, error = {0}", Marshal.GetLastWin32Error());
                                    continue;
                                }
                                    
                                //Console.WriteLine(String.Format("Mutex {0} was removed from process '{1}' with PID {2}.\n", MutexToRemove, p.ProcessName, p.Id));
                                listBox1.Items.Add(String.Format("Mutex {0} was removed from process '{1}' with PID {2}.\n", MutexToRemove, p.ProcessName, p.Id));
                            } catch (Exception)
                            {
                                // do nothing
                                // SHITTY ERROR HANDLING
                            }
                        }
                    }
                }
                System.Threading.Thread.Sleep(500); // lets let this bitch rest sum xDDD
            } // END WHILE
            
        }
    }
}
