; ������������ �������
@Program		MACRO
				.586
				.model	flat,stdcall
				option	casemap:none

				include	\masm32\include\windows.inc
				ENDM

@Uses			MACRO Modules:VARARG
					IRP Module, <Modules>
						include	\masm32\include\&Module.inc
						includelib	\masm32\lib\&Module.lib
					ENDM
				ENDM

@Result			MACRO Params:VARARG
				invoke	Params
				EXITM	<eax>
				ENDM

; �������� ������������ �������� ������
; ��������� ����������� ������
THREAD_DATA	Struc
	Server		Dd ?
	Client		Dd ?
THREAD_DATA	Ends

; SOCKS4 - ����������
CONNECT_SOCK4	Struc
	VN			Db ?
	CD			Db ?
	DSTPORT	Dw ?
	DSTIP		Dd ?
	NULL		Db ?
CONNECT_SOCK4	Ends

; SOCKS4 - ����� ������
RESPONSE_SOCK4	Struc
	VN			Db ?
	CD			Db ?
	DSTPORT	Dw ?
	DSTIP		Dd ?
RESPONSE_SOCK4	Ends
