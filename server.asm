include includes.inc

@Program
@Uses	kernel32, wsock32

; Порт, на котором будет находится наш прокси сервер
SOCKS_PORT		Equ 8080

.code
; Процедуры работы с сокетами
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

; Процедуры реализации SOCKS
; Поток читающий из клиентского и передающий в серверный сокет....
ClientSock	Proc Param:DWORD
			LOCAL sserver, sclient:DWORD
			LOCAL rdFds  :fd_set
			LOCAL	dAmount, lpBuf: DWORD

  	; В Param у нас находится информация о сокетах сервера и клиента, переносим в локальные переменные
	mov		ebx, Param
	Assume  Ebx: Ptr	THREAD_DATA
	mov		eax, [ebx].Server
	mov		sserver, eax
	mov		eax, [ebx].Client
	mov		sclient, eax
	Assume	Ebx : Nothing

  	; Не забудем высвободить память
	invoke	LocalFree, Param
  
@@:
	invoke	FdZero, ADDR rdFds
	invoke	FdSet, sserver, ADDR rdFds
	invoke	FdSet, sclient, ADDR rdFds
	invoke	select, NULL, ADDR rdFds, NULL, NULL, NULL
	; Проверяем, есть ли данные для чтения
	.if eax == SOCKET_ERROR || eax == 0
		; Данных нет - выходим
		jmp  @F
	.endif
	
	; Есть ли данные от сервера, которые нужно передать клиенту?
	invoke FdIsSet, sserver, ADDR rdFds
	.if eax
		; Получаем размер ожидающих чтения данных
		invoke	ioctlsocket, sserver, FIONREAD, ADDR dAmount

		; Резервируем память под данные
		mov		lpBuf, @Result(LocalAlloc, LMEM_FIXED or LMEM_ZEROINIT, dAmount)

		invoke recv, sserver, lpBuf, dAmount, 0
		.if eax == SOCKET_ERROR || eax == 0
			jmp	@F
		.endif
		invoke send, sclient, lpBuf, eax, 0

		invoke	LocalFree, lpBuf
	.endif

	; Есть ли данные от клиента для отправки серверному сокету?
	invoke FdIsSet, sclient, ADDR rdFds
	.if eax
		; Получаем размер ожидающих чтения данных
		invoke	ioctlsocket, sclient, FIONREAD, ADDR dAmount

		; Резервируем память под данные
		mov		lpBuf, @Result(LocalAlloc, LMEM_FIXED or LMEM_ZEROINIT, dAmount)

		invoke recv, sclient, lpBuf, dAmount, 0
		.if eax == SOCKET_ERROR || eax == 0
			jmp	@F
		.endif
		invoke send, sserver, lpBuf, eax, 0

		invoke	LocalFree, lpBuf
	.endif

	; Идем на новый цикл
	jmp    @B
  
@@:
	; Закрываем сокеты
	invoke	closesocket, sserver
	invoke	closesocket, sclient
	
	; Выходим из потока
	invoke	ExitThread, 0
ClientSock	Endp

; Данная функция проверяет запрос клиента и запускает поток обработки данного запроса
socketThread	Proc		sock:DWORD
			LOCAL	lpMem,
					_csock,
					ThreadId,
					dAmount		:DWORD
				
			LOCAL	Remote		:sockaddr_in
			LOCAL	wrFds,
					rdFds		:fd_set
			LOCAL	hResp		:RESPONSE_SOCK4
			
	; Готовимся к чтению данных из сокета
	invoke	FdZero, ADDR rdFds
	invoke	FdSet, sock, ADDR rdFds
	invoke	select, NULL, ADDR rdFds, NULL, NULL, NULL
	; Получаем размер ожидающих чтения данных
	invoke	ioctlsocket, sock, FIONREAD, ADDR dAmount

	; Резервируем память под данные
	mov		lpMem, @Result(LocalAlloc, LMEM_FIXED or LMEM_ZEROINIT, dAmount)
	; Читаем данные запроса из сокета
	invoke	recv, sock, lpMem, dAmount, 0      ; Запрос пришел
	lea		edi, hResp
	mov		esi, lpMem
	
	; В Esi лежит пользовательский запрос. Мы обрабатываем (здесь) только версию SOCKS4,
	; SOCKS5 можно в принципе здесь же обработать, но это позже ...
	Assume	Esi : Ptr	CONNECT_SOCK4
	Assume	Edi : Ptr	RESPONSE_SOCK4
	.if [esi].VN == 4
		; Реализация протокола СОКС 4
		.if [esi].CD == 1
			invoke	socket, AF_INET, SOCK_STREAM, 0
			.if eax != INVALID_SOCKET
				mov		_csock, eax
				; Берем данные удаленного хоста, с которым хочет соединиться клиент
				mov		Remote.sin_family, AF_INET
				mov		ax, [esi].DSTPORT
				mov		Remote.sin_port, ax
				mov		eax, [esi].DSTIP
				mov		Remote.sin_addr, eax
				mov		cx, [esi].DSTPORT
				mov		edx, [esi].DSTIP
				; В Edi лежит ответ пользователю 
				mov		[edi].VN, 0
				mov		[edi].DSTPORT, cx
				mov		[edi].DSTIP, edx
				; Пытаемся соединиться с удаленным сервером                                      
				invoke	connect, _csock, ADDR Remote, SIZEOF Remote
				.if !eax
					; Готовим ответ, что мы соединились
					mov		[edi].CD, 90
					; Отправляем клиенту ответ, содержащий результат попытки соединения
					invoke send, sock, ADDR hResp, SIZEOF RESPONSE_SOCK4, 0
					; Формируем структуру с информацией о серверном и соединенном клиентском сокетах
					; - под серверным здесь подразумеваю сокет соединенный с клиентом, приславшим запрос
					; - под клиентским подразумеваю сокет соединенный с сервером, данные которого запросил клиент 
					mov		ebx, @Result(LocalAlloc, LMEM_FIXED or LMEM_ZEROINIT, SIZEOF THREAD_DATA)
					Assume	Ebx : Ptr	THREAD_DATA
					mov		eax, _csock
					mov		[ebx].Server, eax
					mov		eax, sock
					mov		[ebx].Client, eax
					Assume	Ebx : Nothing
					; Запускаем поток обработки сокетов (читающий из клиентского и передающий в серверный сокет)
					invoke	CreateThread, NULL, NULL, ADDR ClientSock, ebx, NULL, ADDR ThreadId
				.else
					; Если соединение не получилось - закрываем клиентский сокет
					invoke	closesocket, _csock
					; Говорим, что произошла ошибка соединения
					mov		[edi][RESPONSE_SOCK4.CD], 91
					; Отправляем клиенту ответ, содержащий результат попытки соединения
					invoke send, sock, ADDR hResp, SIZEOF RESPONSE_SOCK4, 0
				.endif
			.endif
		.endif
	.endif
	Assume	Edi: Nothing
	Assume	Esi: Nothing
	; Высвобождаем память, выделенную под запрос
	invoke	LocalFree, lpMem
	ret
socketThread	Endp

; Основная процедура, является стартовой для программы
WinMain		Proc
			LOCAL ThreadId, hServSock	:DWORD
			LOCAL hostname[256]	:BYTE
			LOCAL _wsa		:WSADATA
			LOCAL _our		:sockaddr_in

	; Запуск библиотеки работы с сокетами, мы используем функционал версии 1.1, запросим его как минимальный
	invoke	WSAStartup, 0101h, ADDR _wsa
	.if eax == 0
		; Берем свой адрес, подготавливаем структуру, для инициализации серверного сокета
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
		; Вносим порт, на котором хотим слушать входящие сообщения
		mov		ax, SOCKS_PORT
		invoke	htons, eax
		mov		_our.sin_port, ax

		invoke	socket, AF_INET, SOCK_STREAM, 0
		.if eax != INVALID_SOCKET
			; Сохраняем созданный серверный сокет
			mov		hServSock, eax
			; Привязываем серверный сокет к нашему адресу и необходимому порту
			invoke	bind, hServSock, ADDR _our, SIZEOF sockaddr_in
			.if eax != SOCKET_ERROR
			@@:
				; Инициируем сокет на ожидание
				invoke	listen, hServSock, SOMAXCONN
				.repeat
					; Пришел клиент, получаем сокет с пришедшим клиентом
					invoke	accept, hServSock, NULL, NULL
				.until eax != INVALID_SOCKET
				; Создаем поток, в котором будет обрабатываться текущий клиент
				xchg		eax, ebx
				invoke	 CreateThread, NULL, NULL, ADDR socketThread, ebx, NULL, ADDR ThreadId
				; Уходим на ожидание клиентов
				jmp @B
			.endif
		.endif
		invoke	closesocket, hServSock
	.endif

	invoke	ExitProcess, 0
WinMain		Endp
			End	WinMain
