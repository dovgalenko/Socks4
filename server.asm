include includes.inc

@Program
@Uses	kernel32, wsock32

; ����, �� ������� ����� ��������� ��� ������ ������
SOCKS_PORT		Equ 8080

.code
; ��������� ������ � ��������
FdSet		Proc USES Eax Ebx Edx Sock:DWORD, lpFd:DWORD
			LOCAL FdCount:DWORD
			
	mov		ebx, lpFd

	mov		eax, (fd_set Ptr [ebx]).fd_count
	mov		edx, Sock
	push		ebx
	lea		ebx, (fd_set Ptr [ebx]).fd_array
	mov		Dword Ptr [ebx + eax * SIZEOF DWORD], edx
	inc		eax
	pop		ebx
	mov		(fd_set Ptr [ebx]).fd_count, eax
	ret
FdSet		Endp

FdZero		Proc USES Ebx lpFd:DWORD

	mov		ebx, lpFd
	mov		(fd_set Ptr [ebx]).fd_count, 0
	ret
FdZero		Endp

FdIsSet		Proc USES Ebx Ecx Sock:DWORD, lpFd:DWORD
			LOCAL	Result	:DWORD

	mov		Result, FALSE

	mov		ebx, lpFd
	mov		ecx, (fd_set Ptr [ebx]).fd_count
	lea		ebx, (fd_set Ptr [ebx]).fd_array

	.if ecx
		.repeat
			dec   ecx
			mov   eax, Dword Ptr [ebx + ecx * SIZEOF DWORD]
			
			.if eax == Sock
				mov   Result, TRUE
			.endif
		.until Ecx == 0 || Result == TRUE
	.endif

	mov		eax, Result
	ret
FdIsSet          Endp

; ��������� ���������� SOCKS
; ����� �������� �� ����������� � ���������� � ��������� �����....
ClientSock	Proc Param:DWORD
			LOCAL sserver, sclient:DWORD
			LOCAL rdFds  :fd_set
			LOCAL	dAmount, lpBuf: DWORD

  	; � Param � ��� ��������� ���������� � ������� ������� � �������, ��������� � ��������� ����������
	mov		ebx, Param
	Assume  Ebx: Ptr	THREAD_DATA
	mov		eax, [ebx].Server
	mov		sserver, eax
	mov		eax, [ebx].Client
	mov		sclient, eax
	Assume	Ebx : Nothing

  	; �� ������� ����������� ������
	invoke	LocalFree, Param
  
@@:
	invoke	FdZero, ADDR rdFds
	invoke	FdSet, sserver, ADDR rdFds
	invoke	FdSet, sclient, ADDR rdFds
	invoke	select, NULL, ADDR rdFds, NULL, NULL, NULL
	; ���������, ���� �� ������ ��� ������
	.if eax == SOCKET_ERROR || eax == 0
		; ������ ��� - �������
		jmp  @F
	.endif
	
	; ���� �� ������ �� �������, ������� ����� �������� �������?
	invoke FdIsSet, sserver, ADDR rdFds
	.if eax
		; �������� ������ ��������� ������ ������
		invoke	ioctlsocket, sserver, FIONREAD, ADDR dAmount

		; ����������� ������ ��� ������
		mov		lpBuf, @Result(LocalAlloc, LMEM_FIXED or LMEM_ZEROINIT, dAmount)

		invoke recv, sserver, lpBuf, dAmount, 0
		.if eax == SOCKET_ERROR || eax == 0
			jmp	@F
		.endif
		invoke send, sclient, lpBuf, eax, 0

		invoke	LocalFree, lpBuf
	.endif

	; ���� �� ������ �� ������� ��� �������� ���������� ������?
	invoke FdIsSet, sclient, ADDR rdFds
	.if eax
		; �������� ������ ��������� ������ ������
		invoke	ioctlsocket, sclient, FIONREAD, ADDR dAmount

		; ����������� ������ ��� ������
		mov		lpBuf, @Result(LocalAlloc, LMEM_FIXED or LMEM_ZEROINIT, dAmount)

		invoke recv, sclient, lpBuf, dAmount, 0
		.if eax == SOCKET_ERROR || eax == 0
			jmp	@F
		.endif
		invoke send, sserver, lpBuf, eax, 0

		invoke	LocalFree, lpBuf
	.endif

	; ���� �� ����� ����
	jmp    @B
  
@@:
	; ��������� ������
	invoke	closesocket, sserver
	invoke	closesocket, sclient
	
	; ������� �� ������
	invoke	ExitThread, 0
ClientSock	Endp

; ������ ������� ��������� ������ ������� � ��������� ����� ��������� ������� �������
socketThread	Proc		sock:DWORD
			LOCAL	lpMem,
					_csock,
					ThreadId,
					dAmount		:DWORD
				
			LOCAL	Remote		:sockaddr_in
			LOCAL	wrFds,
					rdFds		:fd_set
			LOCAL	hResp		:RESPONSE_SOCK4
			
	; ��������� � ������ ������ �� ������
	invoke	FdZero, ADDR rdFds
	invoke	FdSet, sock, ADDR rdFds
	invoke	select, NULL, ADDR rdFds, NULL, NULL, NULL
	; �������� ������ ��������� ������ ������
	invoke	ioctlsocket, sock, FIONREAD, ADDR dAmount

	; ����������� ������ ��� ������
	mov		lpMem, @Result(LocalAlloc, LMEM_FIXED or LMEM_ZEROINIT, dAmount)
	; ������ ������ ������� �� ������
	invoke	recv, sock, lpMem, dAmount, 0      ; ������ ������
	lea		edi, hResp
	mov		esi, lpMem
	
	; � Esi ����� ���������������� ������. �� ������������ (�����) ������ ������ SOCKS4,
	; SOCKS5 ����� � �������� ����� �� ����������, �� ��� ����� ...
	Assume	Esi : Ptr	CONNECT_SOCK4
	Assume	Edi : Ptr	RESPONSE_SOCK4
	.if [esi].VN == 4
		; ���������� ��������� ���� 4
		.if [esi].CD == 1
			invoke	socket, AF_INET, SOCK_STREAM, 0
			.if eax != INVALID_SOCKET
				mov		_csock, eax
				; ����� ������ ���������� �����, � ������� ����� ����������� ������
				mov		Remote.sin_family, AF_INET
				mov		ax, [esi].DSTPORT
				mov		Remote.sin_port, ax
				mov		eax, [esi].DSTIP
				mov		Remote.sin_addr, eax
				mov		cx, [esi].DSTPORT
				mov		edx, [esi].DSTIP
				; � Edi ����� ����� ������������ 
				mov		[edi].VN, 0
				mov		[edi].DSTPORT, cx
				mov		[edi].DSTIP, edx
				; �������� ����������� � ��������� ��������                                      
				invoke	connect, _csock, ADDR Remote, SIZEOF Remote
				.if !eax
					; ������� �����, ��� �� �����������
					mov		[edi].CD, 90
					; ���������� ������� �����, ���������� ��������� ������� ����������
					invoke send, sock, ADDR hResp, SIZEOF RESPONSE_SOCK4, 0
					; ��������� ��������� � ����������� � ��������� � ����������� ���������� �������
					; - ��� ��������� ����� ������������ ����� ����������� � ��������, ���������� ������
					; - ��� ���������� ������������ ����� ����������� � ��������, ������ �������� �������� ������ 
					mov		ebx, @Result(LocalAlloc, LMEM_FIXED or LMEM_ZEROINIT, SIZEOF THREAD_DATA)
					Assume	Ebx : Ptr	THREAD_DATA
					mov		eax, _csock
					mov		[ebx].Server, eax
					mov		eax, sock
					mov		[ebx].Client, eax
					Assume	Ebx : Nothing
					; ��������� ����� ��������� ������� (�������� �� ����������� � ���������� � ��������� �����)
					invoke	CreateThread, NULL, NULL, ADDR ClientSock, ebx, NULL, ADDR ThreadId
				.else
					; ���� ���������� �� ���������� - ��������� ���������� �����
					invoke	closesocket, _csock
					; �������, ��� ��������� ������ ����������
					mov		[edi][RESPONSE_SOCK4.CD], 91
					; ���������� ������� �����, ���������� ��������� ������� ����������
					invoke send, sock, ADDR hResp, SIZEOF RESPONSE_SOCK4, 0
				.endif
			.endif
		.endif
	.endif
	Assume	Edi: Nothing
	Assume	Esi: Nothing
	; ������������ ������, ���������� ��� ������
	invoke	LocalFree, lpMem
	ret
socketThread	Endp

; �������� ���������, �������� ��������� ��� ���������
WinMain		Proc
			LOCAL ThreadId, hServSock	:DWORD
			LOCAL hostname[256]	:BYTE
			LOCAL _wsa		:WSADATA
			LOCAL _our		:sockaddr_in

	; ������ ���������� ������ � ��������, �� ���������� ���������� ������ 1.1, �������� ��� ��� �����������
	invoke	WSAStartup, 0101h, ADDR _wsa
	.if eax == 0
		; ����� ���� �����, �������������� ���������, ��� ������������� ���������� ������
		invoke	gethostname, ADDR hostname, 256
		invoke	gethostbyname, ADDR hostname
		.if eax == 0
			invoke	inet_addr, ADDR hostname
		.else
			mov		eax, [eax + 12]
			mov		eax, [eax]
			mov		eax, [eax]
		.endif
		mov		_our.sin_addr, eax
		invoke	inet_ntoa, eax

		mov		_our.sin_family, AF_INET
		mov		_our.sin_addr.S_un.S_addr, INADDR_ANY
		xor		eax, eax
		; ������ ����, �� ������� ����� ������� �������� ���������
		mov		ax, SOCKS_PORT
		invoke	htons, eax
		mov		_our.sin_port, ax

		invoke	socket, AF_INET, SOCK_STREAM, 0
		.if eax != INVALID_SOCKET
			; ��������� ��������� ��������� �����
			mov		hServSock, eax
			; ����������� ��������� ����� � ������ ������ � ������������ �����
			invoke	bind, hServSock, ADDR _our, SIZEOF sockaddr_in
			.if eax != SOCKET_ERROR
			@@:
				; ���������� ����� �� ��������
				invoke	listen, hServSock, SOMAXCONN
				.repeat
					; ������ ������, �������� ����� � ��������� ��������
					invoke	accept, hServSock, NULL, NULL
				.until eax != INVALID_SOCKET
				; ������� �����, � ������� ����� �������������� ������� ������
				xchg		eax, ebx
				invoke	 CreateThread, NULL, NULL, ADDR socketThread, ebx, NULL, ADDR ThreadId
				; ������ �� �������� ��������
				jmp @B
			.endif
		.endif
		invoke	closesocket, hServSock
	.endif

	invoke	ExitProcess, 0
WinMain		Endp
			End	WinMain
