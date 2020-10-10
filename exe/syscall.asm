
public sysp

.code

sysp PROC
	mov	r10, rcx
	mov eax, 2000h
	syscall
	ret
sysp ENDP

END