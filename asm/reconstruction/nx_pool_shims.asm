; AMD64 MASM source, native-UASM verified; experimental writer uses these bytes.
; Converts ONLY PoolType == NonPagedPool (0) to NonPagedPoolNx (200h).
; Tail jumps retain the caller's stack and original imported API implementation.
; No stack allocation, saved nonvolatile register, CALL or unwind entry required.
; See reports/PERMISSION_REVIEW.md and reports/NX_MANIFEST.md for evidence/limits.
option casemap:none
EXTERN __imp_ExAllocatePool:QWORD
EXTERN __imp_ExAllocatePoolWithTag:QWORD
PUBLIC MC808_NxExAllocatePool
PUBLIC MC808_NxExAllocatePoolWithTag
.code
ALIGN 16
MC808_NxExAllocatePool PROC
    test ecx, ecx
    jne short pool_passthrough
    mov ecx, 200h
pool_passthrough:
    jmp QWORD PTR [__imp_ExAllocatePool]
MC808_NxExAllocatePool ENDP
    db 0CCh ; fixed one-byte padding: second shim starts 16 bytes after first
MC808_NxExAllocatePoolWithTag PROC
    test ecx, ecx
    jne short tagged_passthrough
    mov ecx, 200h
tagged_passthrough:
    jmp QWORD PTR [__imp_ExAllocatePoolWithTag]
MC808_NxExAllocatePoolWithTag ENDP
    db 0CCh
END
