
public sysp

.code

sysp PROC
	mov r10, rcx
	mov eax, 321h
	syscall
	ret
sysp ENDP

END