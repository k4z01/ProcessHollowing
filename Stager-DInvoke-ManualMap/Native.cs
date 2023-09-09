// Author: Ryan Cobb (@cobbr_io), The Wover (@TheRealWover)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using System.Runtime.InteropServices;


/// <summary>
/// Contains function prototypes and wrapper functions for dynamically invoking NT API Calls.
/// </summary>
public static class Native
{
    public static DataNative.NTSTATUS NtCreateThreadEx(ref IntPtr threadHandle, DataWin32.WinNT.ACCESS_MASK desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr startAddress, IntPtr parameter, bool createSuspended, int stackZeroBits, int sizeOfStack, int maximumStackSize, IntPtr attributeList)
    {
        object[] funcargs =
        {
            threadHandle, desiredAccess, objectAttributes, processHandle, startAddress, parameter, createSuspended, stackZeroBits,
            sizeOfStack, maximumStackSize, attributeList
        };

        var retValue = (DataNative.NTSTATUS)Generic.DynamicApiInvoke("ntdll.dll", "NtCreateThreadEx",
            typeof(Delegates.NtCreateThreadEx), ref funcargs);

        threadHandle = (IntPtr)funcargs[0];
        return retValue;
    }

    public static DataNative.NTSTATUS NtCreateSection(ref IntPtr sectionHandle, uint desiredAccess, IntPtr objectAttributes, ref ulong maximumSize, uint sectionPageProtection, uint allocationAttributes, IntPtr fileHandle)
    {
        object[] funcargs =
        {
            sectionHandle, desiredAccess, objectAttributes, maximumSize, sectionPageProtection, allocationAttributes, fileHandle
        };

        var retValue = (DataNative.NTSTATUS)Generic.DynamicApiInvoke("ntdll.dll", "NtCreateSection", typeof(Delegates.NtCreateSection), ref funcargs);
            
        if (retValue != DataNative.NTSTATUS.Success)
            throw new InvalidOperationException("Unable to create section, " + retValue);

        sectionHandle = (IntPtr) funcargs[0];
        maximumSize = (ulong) funcargs[3];

        return retValue;
    }

    public static DataNative.NTSTATUS NtUnmapViewOfSection(IntPtr hProc, IntPtr baseAddr)
    {
        object[] funcargs =
        {
            hProc, baseAddr
        };

        var result = (DataNative.NTSTATUS)Generic.DynamicApiInvoke("ntdll.dll", "NtUnmapViewOfSection", typeof(Delegates.NtUnmapViewOfSection), ref funcargs);

        return result;
    }

    public static DataNative.NTSTATUS NtMapViewOfSection(IntPtr sectionHandle, IntPtr processHandle, ref IntPtr baseAddress, IntPtr zeroBits, IntPtr commitSize, IntPtr sectionOffset, ref ulong viewSize, uint inheritDisposition, uint allocationType, uint win32Protect)
    {
        object[] funcargs =
        {
            sectionHandle, processHandle, baseAddress, zeroBits, commitSize, sectionOffset, viewSize, inheritDisposition, allocationType,
            win32Protect
        };

        var retValue = (DataNative.NTSTATUS)Generic.DynamicApiInvoke("ntdll.dll", "NtMapViewOfSection", typeof(Delegates.NtMapViewOfSection), ref funcargs);
            
        if (retValue != DataNative.NTSTATUS.Success && retValue != DataNative.NTSTATUS.ImageNotAtBase)
            throw new InvalidOperationException("Unable to map view of section, " + retValue);

        baseAddress = (IntPtr) funcargs[2];
        viewSize = (ulong) funcargs[6];

        return retValue;
    }

    public static void RtlInitUnicodeString(ref DataNative.UNICODE_STRING destinationString, [MarshalAs(UnmanagedType.LPWStr)] string sourceString)
    {
        object[] funcargs =
        {
            destinationString, sourceString
        };

        Generic.DynamicApiInvoke("ntdll.dll", "RtlInitUnicodeString", typeof(Delegates.RtlInitUnicodeString), ref funcargs);

        destinationString = (DataNative.UNICODE_STRING)funcargs[0];
    }

    public static DataNative.NTSTATUS LdrLoadDll(IntPtr pathToFile, uint dwFlags, ref DataNative.UNICODE_STRING moduleFileName, ref IntPtr moduleHandle)
    {
        object[] funcargs =
        {
            pathToFile, dwFlags, moduleFileName, moduleHandle
        };

        var retValue = (DataNative.NTSTATUS)Generic.DynamicApiInvoke("ntdll.dll", "LdrLoadDll", typeof(Delegates.LdrLoadDll), ref funcargs);

        moduleHandle = (IntPtr)funcargs[3];

        return retValue;
    }

    public static void RtlZeroMemory(IntPtr destination, int length)
    {
        object[] funcargs =
        {
            destination, length
        };

        Generic.DynamicApiInvoke("ntdll.dll", "RtlZeroMemory", typeof(Delegates.RtlZeroMemory), ref funcargs);
    }

    public static DataNative.NTSTATUS NtQueryInformationProcess(IntPtr hProcess, DataNative.PROCESSINFOCLASS processInfoClass, out IntPtr pProcInfo)
    {
        int processInformationLength;
        uint retLen = 0;

        switch (processInfoClass)
        {
            case DataNative.PROCESSINFOCLASS.ProcessWow64Information:
                pProcInfo = Marshal.AllocHGlobal(IntPtr.Size);
                RtlZeroMemory(pProcInfo, IntPtr.Size);
                processInformationLength = IntPtr.Size;
                break;
                
            case DataNative.PROCESSINFOCLASS.ProcessBasicInformation:
                var pbi = new DataNative.PROCESS_BASIC_INFORMATION();
                pProcInfo = Marshal.AllocHGlobal(Marshal.SizeOf(pbi));
                RtlZeroMemory(pProcInfo, Marshal.SizeOf(pbi));
                Marshal.StructureToPtr(pbi, pProcInfo, true);
                processInformationLength = Marshal.SizeOf(pbi);
                break;
                
            default:
                throw new InvalidOperationException($"Invalid ProcessInfoClass: {processInfoClass}");
        }

        object[] funcargs =
        {
            hProcess, processInfoClass, pProcInfo, processInformationLength, retLen
        };

        var retValue = (DataNative.NTSTATUS)Generic.DynamicApiInvoke("ntdll.dll", "NtQueryInformationProcess", typeof(Delegates.NtQueryInformationProcess), ref funcargs);
            
        if (retValue != DataNative.NTSTATUS.Success)
            throw new UnauthorizedAccessException("Access is denied.");

        pProcInfo = (IntPtr)funcargs[2];

        return retValue;
    }

    public static bool NtQueryInformationProcessWow64Information(IntPtr hProcess)
    {
        var retValue = NtQueryInformationProcess(hProcess, DataNative.PROCESSINFOCLASS.ProcessWow64Information, out var pProcInfo);
            
        if (retValue != DataNative.NTSTATUS.Success)
            throw new UnauthorizedAccessException("Access is denied.");

        return Marshal.ReadIntPtr(pProcInfo) != IntPtr.Zero;
    }

    public static DataNative.PROCESS_BASIC_INFORMATION NtQueryInformationProcessBasicInformation(IntPtr hProcess)
    {
        var retValue = NtQueryInformationProcess(hProcess, DataNative.PROCESSINFOCLASS.ProcessBasicInformation, out var pProcInfo);
            
        if (retValue != DataNative.NTSTATUS.Success)
            throw new UnauthorizedAccessException("Access is denied.");

        return (DataNative.PROCESS_BASIC_INFORMATION)Marshal.PtrToStructure(pProcInfo, typeof(DataNative.PROCESS_BASIC_INFORMATION));
    }

    public static IntPtr NtAllocateVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress, IntPtr zeroBits, ref IntPtr regionSize, uint allocationType, uint protect)
    {
        object[] funcargs =
        {
            processHandle, baseAddress, zeroBits, regionSize, allocationType, protect
        };

        var retValue = (DataNative.NTSTATUS)Generic.DynamicApiInvoke("ntdll.dll", "NtAllocateVirtualMemory", typeof(Delegates.NtAllocateVirtualMemory), ref funcargs);
            
        switch (retValue)
        {
            case DataNative.NTSTATUS.AccessDenied:
                throw new UnauthorizedAccessException("Access is denied.");
            case DataNative.NTSTATUS.AlreadyCommitted:
                throw new InvalidOperationException("The specified address range is already committed.");
            case DataNative.NTSTATUS.CommitmentLimit:
                throw new InvalidOperationException("Your system is low on virtual memory.");
            case DataNative.NTSTATUS.ConflictingAddresses:
                throw new InvalidOperationException("The specified address range conflicts with the address space.");
            case DataNative.NTSTATUS.InsufficientResources:
                throw new InvalidOperationException("Insufficient system resources exist to complete the API call.");
            case DataNative.NTSTATUS.InvalidHandle:
                throw new InvalidOperationException("An invalid HANDLE was specified.");
            case DataNative.NTSTATUS.InvalidPageProtection:
                throw new InvalidOperationException("The specified page protection was not valid.");
            case DataNative.NTSTATUS.NoMemory:
                throw new InvalidOperationException("Not enough virtual memory or paging file quota is available to complete the specified operation.");
            case DataNative.NTSTATUS.ObjectTypeMismatch:
                throw new InvalidOperationException("There is a mismatch between the type of object that is required by the requested operation and the type of object that is specified in the request.");
        }

        if (retValue != DataNative.NTSTATUS.Success)
            throw new InvalidOperationException("An attempt was made to duplicate an object handle into or out of an exiting process.");

        baseAddress = (IntPtr)funcargs[1];
        return baseAddress;
    }

    public static void NtFreeVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress, ref IntPtr regionSize, uint freeType)
    {
        object[] funcargs =
        {
            processHandle, baseAddress, regionSize, freeType
        };

        var retValue = (DataNative.NTSTATUS)Generic.DynamicApiInvoke("ntdll.dll", "NtFreeVirtualMemory", typeof(Delegates.NtFreeVirtualMemory), ref funcargs);
            
        switch (retValue)
        {
            case DataNative.NTSTATUS.AccessDenied:
                throw new UnauthorizedAccessException("Access is denied.");
            case DataNative.NTSTATUS.InvalidHandle:
                throw new InvalidOperationException("An invalid HANDLE was specified.");
        }

        if (retValue != DataNative.NTSTATUS.Success)
            throw new InvalidOperationException("There is a mismatch between the type of object that is required by the requested operation and the type of object that is specified in the request.");
    }
        
    public static uint NtProtectVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress, ref IntPtr regionSize, uint newProtect)
    {
        uint oldProtect = 0;
        object[] funcargs =
        {
            processHandle, baseAddress, regionSize, newProtect, oldProtect
        };

        var retValue = (DataNative.NTSTATUS)Generic.DynamicApiInvoke("ntdll.dll", "NtProtectVirtualMemory", typeof(Delegates.NtProtectVirtualMemory), ref funcargs);
            
        if (retValue != DataNative.NTSTATUS.Success)
            throw new InvalidOperationException("Failed to change memory protection, " + retValue);

        oldProtect = (uint)funcargs[4];
        return oldProtect;
    }

    public static uint NtWriteVirtualMemory(IntPtr processHandle, IntPtr baseAddress, IntPtr buffer, uint bufferLength)
    {
        uint bytesWritten = 0;
        object[] funcargs =
        {
            processHandle, baseAddress, buffer, bufferLength, bytesWritten
        };

        var retValue = (DataNative.NTSTATUS)Generic.DynamicApiInvoke("ntdll.dll", "NtWriteVirtualMemory", typeof(Delegates.NtWriteVirtualMemory), ref funcargs);
            
        if (retValue != DataNative.NTSTATUS.Success)
            throw new InvalidOperationException("Failed to write memory, " + retValue);

        bytesWritten = (uint)funcargs[4];
        return bytesWritten;
    }

    public static IntPtr LdrGetProcedureAddress(IntPtr hModule, IntPtr functionName, IntPtr ordinal, ref IntPtr functionAddress)
    {
        object[] funcargs =
        {
            hModule, functionName, ordinal, functionAddress
        };

        var retValue = (DataNative.NTSTATUS)Generic.DynamicApiInvoke("ntdll.dll", "LdrGetProcedureAddress", typeof(Delegates.LdrGetProcedureAddress), ref funcargs);
            
        if (retValue != DataNative.NTSTATUS.Success)
            throw new InvalidOperationException("Failed get procedure address, " + retValue);

        functionAddress = (IntPtr)funcargs[3];
        return functionAddress;
    }

    public static void RtlGetVersion(ref DataNative.OSVERSIONINFOEX versionInformation)
    {
        object[] funcargs =
        {
            versionInformation
        };

        var retValue = (DataNative.NTSTATUS)Generic.DynamicApiInvoke("ntdll.dll", "RtlGetVersion", typeof(Delegates.RtlGetVersion), ref funcargs);
            
        if (retValue != DataNative.NTSTATUS.Success)
            throw new InvalidOperationException("Failed get procedure address, " + retValue);

        versionInformation = (DataNative.OSVERSIONINFOEX)funcargs[0];
    }

    public static IntPtr NtOpenFile(ref IntPtr fileHandle, DataWin32.Kernel32.FileAccessFlags desiredAccess, ref DataNative.OBJECT_ATTRIBUTES objectAttributes, ref DataNative.IO_STATUS_BLOCK ioStatusBlock, DataWin32.Kernel32.FileShareFlags shareAccess, DataWin32.Kernel32.FileOpenFlags openOptions)
    {
        object[] funcargs =
        {
            fileHandle, desiredAccess, objectAttributes, ioStatusBlock, shareAccess, openOptions
        };

        var retValue = (DataNative.NTSTATUS)Generic.DynamicApiInvoke(@"ntdll.dll", @"NtOpenFile", typeof(Delegates.NtOpenFile), ref funcargs);
            
        if (retValue != DataNative.NTSTATUS.Success)
            throw new InvalidOperationException("Failed to open file, " + retValue);

        fileHandle = (IntPtr)funcargs[0];
        return fileHandle;
    }

    /// <summary>
    /// Holds delegates for API calls in the NT Layer.
    /// Must be public so that they may be used with SharpSploit.Execution.DynamicInvoke.Generic.DynamicFunctionInvoke
    /// </summary>
    /// <example>
    /// 
    /// // These delegates may also be used directly.
    ///
    /// // Get a pointer to the NtCreateThreadEx function.
    /// IntPtr pFunction = Execution.DynamicInvoke.Generic.GetLibraryAddress(@"ntdll.dll", "NtCreateThreadEx");
    /// 
    /// //  Create an instance of a NtCreateThreadEx delegate from our function pointer.
    /// DELEGATES.NtCreateThreadEx createThread = (NATIVE_DELEGATES.NtCreateThreadEx)Marshal.GetDelegateForFunctionPointer(
    ///    pFunction, typeof(NATIVE_DELEGATES.NtCreateThreadEx));
    ///
    /// //  Invoke NtCreateThreadEx using the delegate
    /// createThread(ref threadHandle, Data.Win32.WinNT.ACCESS_MASK.SPECIFIC_RIGHTS_ALL | Data.Win32.WinNT.ACCESS_MASK.STANDARD_RIGHTS_ALL, IntPtr.Zero,
    ///     procHandle, startAddress, IntPtr.Zero, Data.Native.NT_CREATION_FLAGS.HIDE_FROM_DEBUGGER, 0, 0, 0, IntPtr.Zero);
    /// 
    /// </example>
    private struct Delegates
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate DataNative.NTSTATUS NtCreateThreadEx(
            out IntPtr threadHandle,
            DataWin32.WinNT.ACCESS_MASK desiredAccess,
            IntPtr objectAttributes,
            IntPtr processHandle,
            IntPtr startAddress,
            IntPtr parameter,
            bool createSuspended,
            int stackZeroBits,
            int sizeOfStack,
            int maximumStackSize,
            IntPtr attributeList);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate DataNative.NTSTATUS NtCreateSection(
            ref IntPtr sectionHandle,
            uint desiredAccess,
            IntPtr objectAttributes,
            ref ulong maximumSize,
            uint sectionPageProtection,
            uint allocationAttributes,
            IntPtr fileHandle);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate DataNative.NTSTATUS NtUnmapViewOfSection(
            IntPtr hProc,
            IntPtr baseAddr);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate DataNative.NTSTATUS NtMapViewOfSection(
            IntPtr sectionHandle,
            IntPtr processHandle,
            out IntPtr baseAddress,
            IntPtr zeroBits,
            IntPtr commitSize,
            IntPtr sectionOffset,
            out ulong viewSize,
            uint inheritDisposition,
            uint allocationType,
            uint win32Protect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint LdrLoadDll(
            IntPtr pathToFile,
            uint dwFlags,
            ref DataNative.UNICODE_STRING moduleFileName,
            ref IntPtr moduleHandle);
            
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate void RtlInitUnicodeString(
            ref DataNative.UNICODE_STRING destinationString,
            [MarshalAs(UnmanagedType.LPWStr)]
            string sourceString);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate void RtlZeroMemory(
            IntPtr destination,
            int length);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtQueryInformationProcess(
            IntPtr processHandle,
            DataNative.PROCESSINFOCLASS processInformationClass,
            IntPtr processInformation,
            int processInformationLength,
            ref uint returnLength);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtAllocateVirtualMemory(
            IntPtr processHandle,
            ref IntPtr baseAddress,
            IntPtr zeroBits,
            ref IntPtr regionSize,
            uint allocationType,
            uint protect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtFreeVirtualMemory(
            IntPtr processHandle,
            ref IntPtr baseAddress,
            ref IntPtr regionSize,
            uint freeType);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtProtectVirtualMemory(
            IntPtr processHandle,
            ref IntPtr baseAddress,
            ref IntPtr regionSize,
            uint newProtect,
            ref uint oldProtect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtWriteVirtualMemory(
            IntPtr processHandle,
            IntPtr baseAddress,
            IntPtr buffer,
            uint bufferLength,
            ref uint bytesWritten);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint LdrGetProcedureAddress(
            IntPtr hModule,
            IntPtr functionName,
            IntPtr ordinal,
            ref IntPtr functionAddress);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint RtlGetVersion(
            ref DataNative.OSVERSIONINFOEX versionInformation);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtOpenFile(
            ref IntPtr fileHandle,
            DataWin32.Kernel32.FileAccessFlags accessFlags,
            ref DataNative.OBJECT_ATTRIBUTES objectAttributes,
            ref DataNative.IO_STATUS_BLOCK ioStatusBlock,
            DataWin32.Kernel32.FileShareFlags shareAccess,
            DataWin32.Kernel32.FileOpenFlags openOptions);
    }
}