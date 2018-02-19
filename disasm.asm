; @Author: Ainoras Žukauskas VU MIF PS group 4 subgroup 2

.MODEL small
.STACK 100h

.DATA
arg_msg 		DB "Ainoras Zukauskas Programu sistemos 4 grupe 2 pogrupis.",13,10
arg2_msg 		DB "Programa kuri vercia masininy koda i assemblery.$"
cant_open 		DB 13,10,"Can't open",13,10,'$'		; Message for file open error
file_n 			DB 40 DUP(0)				; Input File name
output_n 		DB 40 DUP(0)				; Output file name
in_handle 		DW 0						; File handles
out_handle 		DW 0
temp_index 		DW 0						; Temporary index for input file
bytes_read 		DW 0						; Bytes read on input

;WRITING SYMBOLS
new_line 		DB 13,10
point 			DB ","
doublepoint 	DB ":"
space 			DB 9 DUP(" ")
left_brack 		DB "["
right_brack 	DB "]"
byte_ptr 		DB "byte ptr "
word_ptr 		DB "word ptr "
invalid_msg 	DB "(Arg invalid) "
far_msg 		DB "far "
add_sym			DB "+"
sub_sym 		DB "-"
;WRITING SYMBOLS END

;Analyzed byte
c_opName 		DW 0	; Operation code names adress
c_abyte 		DB 0	; Is there an adress byte? (1 yes, 0 no)
c_width 		DB 0	; Word or byte? (1 word, 0 byte)
c_is_reg 		DB 0 	; Is there a predefined register? (1 yes, 0 no)
c_reg_val		DW 0	; Predefined register value (Adress)
c_arg_1 		DB 0	; First argument of analyzed byte
c_arg_2 		DB 0	; Second argument of analyzed byte
c_is_sr 		DB 0	; Is there a segment register in adress byte ()?
c_sr			DB 0	; Not used currently
;Analyzed byte end

; Analyzed adress byte
a_mod 			DW 0				; Adress byte mod
a_reg 			DW 0				; Adress byte reg
a_rm			DW 0				; Adress byte register/memory
;Analyzed adress byte end

v_arg_1 		DB 40 DUP("$")		; First argument string
v_arg_2 		DB 40 DUP("$")		; Second argument string

v_arg_index 	DW 0				; Argument index (For both v_arg_1 and v_arg_2)
cur_arg_buff 	DW 0				; Adress of the current argument buffer = offset (v_arg_1 or v_arg_2)

temp_bytes 		DB 25 DUP(" "), '$'	; The read bytes for current command
temp_b_index 	DW 0				; The index of temp_bytes buffer

ip_index 		DW 100h				; The current IP value
ip_value 		DB 4 DUP("$")		; The current IP value in ASCII
ip_arr_index 	DW 0				; The index of ip_value buffer
temp_ip_add 	DW 0 				; The number of bytes currently read (For IP adding)

needs_convert 	DW 0
counter_convert DW 0

; Analyze byte

opcInfo struc						; Equivalent structure for analyzing bytes
	s_opName 	DW 0
	s_abyte 	DB 0
	s_width 	DB 0
	s_is_reg 	DB 0
	s_reg_val	DW 0
	s_arg_1 	DB 0
	s_arg_2 	DB 0
	s_is_sr 	DB 0
ends

include opTable.inc

hex				DB "0123456789ABCDEF"	; Hex base
temp_prefix 	DW noReg				; Adress to prefix (if found). Stored for 1 opc read

; Extra identifying of operation code

identifyx80 	DW opcAdd, opcOr, opcAdc, opcSbb, opcAnd, opcSub, opcXor, opcCmp
identifyxD0		DW opcRol, opcUnk, opcUnk, opcUnk, opcUnk, opcUnk, opcUnk, opcUnk
identifyxF6 	DW opcTest, opcUnk, opcNot, opcNeg, opcMul, opcIMul, opcDiv, opcIDiv
identifyxFE 	DW opcInc, opcDec, opcUnk, opcUnk, opcUnk, opcUnk, opcUnk, opcUnk
identifyxFF 	DW opcInc, opcDec, opcCall, opcCall, opcJmp, opcJmp, opcPush, opcUnk

regRM_w0		DW regAL, regCL, regDL, regBL, regAH, regCH, regDH, regBH
regRM_w1		DW regAX, regCX, regDX, regBX, regSP, regBP, regSI, regDI

rm_00			DW rm_000_00, rm_001_00, rm_010_00, rm_011_00, rm_100_00, rm_101_00, rm_110_00, rm_111_00
				;  "BX+SI$"   "BX+DI$"   "BP+SI$"   "BP+DI$"   "SI$"      "DI$"      "$"        "BX$"
rm_01			DW rm_000_01, rm_001_01, rm_010_01, rm_011_01, rm_100_01, rm_101_01, rm_110_01, rm_111_01
				;  "BX+SI+$"  "BX+DI+$"  "BP+SI+$"  "BP+DI+$"  "SI+$"     "DI+$"     "BP+$"     "BX+$"

.DATA?
input_buff 		DB 257 DUP(?)			; Input buffer
outpt_buff 		DB 257 DUP(?)			; Output buffer

.CODE
start:
	MOV 	AX, @DATA
	MOV 	DS, AX

	MOV 	SI, 0081h				; Set start of arguments
	MOV 	BX, 0					; Count index of argument file name
	MOV 	CX, -1					; Count amount of arguments

ARG_PARSE:
	MOV 	AL, byte ptr ES:[SI]	; Store next char of arguments

	CMP 	AL, 13					; End of arguments (newline)
	JE 		CHECK_ERRORS			; Check if right amount of arguments

	CMP 	AL, ' '					; End of this argument, skip space
	JE 		SKIP_SPACE

	CMP 	AL, '/'					; Check if "/?" is trying to be written
	JE		ERR_TEST

	INC 	SI						; Store this character to appropriate array
	JMP 	WRITE

ERR_TEST:
	INC	 	SI
	MOV 	AL, byte ptr ES:[SI]	; Check if next byte is '?'
	CMP 	AL, '?'
	JNE		WRITE_INIT				; If no, continue with write
ERROR:
	MOV 	DX, OFFSET arg_msg		; Error message
	MOV 	AH, 09
	INT 	21h

	MOV 	AX, 4C00H
	INT 	21h

NO_OPEN:							; Cant open/write file
	MOV 	DX, offset cant_open
	MOV 	AH, 09
	INT 	21h
JMP ERROR

WRITE_INIT:							; Fix before write (After ERR_TEST)
	DEC		SI
	MOV 	AL, byte ptr ES:[SI]
	INC 	SI
JMP WRITE

SKIP_SPACE:							; Skips the space, shifts to next array
	INC 	SI
	MOV 	AL, byte ptr ES:[SI]
	CMP 	AL, ' '					; Skip all the spaces
	JE 		SKIP_SPACE
	INC 	CX						; Sets which array should be used
	MOV 	BX, 0					; Index of new array is 0
JMP ARG_PARSE

CHECK_ERRORS:						; Only continue if there are 3 arguments
	CMP 	CX, 1
	JE		CONTINUE

	CMP 	CX, 2					; In case there is a space before newline
	JE 		CONTINUE
JMP ERROR

WRITE:								; Write to appropriate parameter
	CMP 	CX, 0
	JE		FIRST_PARAM

	CMP 	CX, 1
	JE		SECOND_PARAM
JMP ERROR							; If there are more arguments, error

FIRST_PARAM:
	MOV 	[file_n+BX], AL			; First param
	INC 	BX
JMP ARG_PARSE

SECOND_PARAM:
	MOV 	[output_n+BX], AL			; Second param
	INC 	BX
JMP ARG_PARSE

CONTINUE:
	INT 3h							; Debug
	CLC								; Clear carry

	MOV 	DX, OFFSET file_n	 	; Atidaryti  input faila
	MOV 	AX, 3D00h
	INT 	21h

	CALL 	check_carry				; Check if successful

	MOV 	in_handle, AX				; Store handle

	MOV 	CX, 0
	MOV 	DX, OFFSET output_n		; Open output file
	MOV 	AX, 3C00h
	INT 	21h

	CALL 	check_carry				; check if success

	MOV 	out_handle, AX		; save handle

	MOV 	AX, 0
	MOV 	BX, 0
	MOV 	CX, 0
	MOV  	DX, 0

PARSE:								; The whole algorithm
	CALL 	check_read				; Check if new input has to be read
	MOV 	CX, [bytes_read]
	CMP 	CX, 0					; Check if any bytes left in file
	JLE 	EXIT					; nothing left in file, quit

	CALL 	store_next_byte			; Get the next byte for opc
	CALL	recognize_byte			; Recognize the next opc
	CALL 	analyze_byte			; Do work with recognized opc

JMP PARSE

EXIT:
	MOV 	AX, 0
TERMINATE:
	MOV 	AH, 4Ch
	INT 	21h

analyze_byte proc
	PUSH 	AX
	PUSH 	BX
	PUSH 	CX
	PUSH 	DX
	; Analyze the current byte, get all the needed arguments and print

	MOV 	BX, c_opName

	MOV 	CX, offset opcPrefix		;If operation code is prefix, store
	CMP 	BX, CX
	JE 		PREFIX_STORE

	MOV 	CX, offset opcUnk			;If operation code is unknown, write
	CMP		BX, CX
	JNE		KNOWN
	JMP FINALIZE

	PREFIX_STORE:
		MOV 	AX, c_reg_val
		MOV 	temp_prefix, AX

		POP 	DX
		POP 	CX
		POP 	BX
		POP 	AX
		RET
	KNOWN:
		MOV 	BL, c_abyte
		CMP 	BL, 0
		JE		STILL_KNOWN		; If no adress byte then cant be extra_identify

		CALL 	analyze_adress_byte		;Analyze the adress byte
		CALL 	extra_identify			;Set extra identity

		MOV 	BX, c_opName			;Check if not unknwon (again)
		MOV 	CX, offset opcUnk
		CMP		BX, CX
		JNE		STILL_KNOWN				; Get arguments
	JMP FINALIZE

	STILL_KNOWN:
		CALL 	get_args

	FINALIZE:
		CALL	write_proc

		MOV 	AX, offset noReg	;Atstatom prefix
		MOV 	temp_prefix, AX

		POP 	DX
		POP 	CX
		POP 	BX
		POP 	AX
		RET
analyze_byte endp

get_args proc
	PUSH 	AX
	PUSH 	BX
	PUSH 	CX
	PUSH 	DX
	;ARG1
	MOV 	AX, offset v_arg_1
	MOV 	cur_arg_buff, AX
	MOV 	v_arg_index, 0
	MOV 	BL, c_arg_1
	CALL 	arg_checker
	;ARG1 END
	;ARG2
	MOV 	AX, offset v_arg_2
	MOV 	cur_arg_buff, AX
	MOV 	v_arg_index, 0
	MOV 	BL, c_arg_2
	CALL 	arg_checker
	;ARG2 END

	POP 	DX
	POP 	CX
	POP 	BX
	POP 	AX
	RET
get_args endp

convert_number proc
	; Convert given bytes as a number in hex
	; CL is how many bytes the number has
	; AX is number to be converted
	MOV 	BX, cur_arg_buff
	MOV  	DX, offset v_arg_index
	MOV 	needs_convert, BX
	MOV 	counter_convert, DX
	CALL 	number_to_ascii
	RET
convert_number endp

store_as_text proc
	; Argument part stored as text until $ (DX is memory adr)
	PUSH 	AX
	PUSH 	BX
	PUSH 	CX
	PUSH 	DX
	STORE_T_LOOP:
		MOV 	BX, DX
		MOV 	AL, [BX]
		CMP 	AL, "$"
		JE 		FINISH_STORE

		MOV 	BX, cur_arg_buff
		MOV 	CX, v_arg_index
		ADD 	BX, CX
		MOV 	[BX], AL
		MOV 	AX, v_arg_index
		INC 	AX
		MOV 	v_arg_index, AX

		INC 	DX
		JMP 	STORE_T_LOOP

	FINISH_STORE:
		POP 	DX
		POP 	CX
		POP 	BX
		POP 	AX

		RET
store_as_text endp

store_as_number proc
	; Find if number should be 2 or 4 bytes and convert
	; Gets the needed bytes
	CALL	store_next_byte				; Get next byte (IN DL)

	MOV 	CH, c_width					; Store width of argument
	MOV 	AX, 0

	MOV 	AL, DL						; Set it to AL
	MOV 	CL, 2						; Set to byte size
	CMP 	CH, 0						; If width is byte
	JE 		STORE_NUM					; Store
	CALL 	store_next_byte				; ELSE: width is word
	MOV 	CL, 4						; size is 4
	MOV 	AH, DL						; Store DL to AH
	STORE_NUM:
		CALL 	convert_number
		RET
store_as_number endp

ident_rm proc
	;Returns proper rm adress
	;RESULT: DX
	PUSH 	AX
	PUSH 	BX
	PUSH 	CX

	MOV 	AX, a_mod
	CMP 	AX, 0
	JE 		MOD_0

	MOV 	BX, offset rm_01
	JMP 	FIND_RM
	MOD_0:
		MOV 	BX, offset rm_00
	FIND_RM:
		MOV 	AH, 0
		MOV 	AL, byte ptr a_rm
		MOV 	DH, 0
		MOV 	DL, 2
		MUL 	DL

		ADD 	BX, AX
		MOV 	DX, [BX]

	POP 	CX
	POP 	BX
	POP 	AX
	RET
ident_rm endp

put_single_char proc
	;Puts char in DL to adress in cur_arg_buf
	;RESULT: In v_arg_1 or v_arg_2
	PUSH 	SI
	PUSH 	BX

	MOV 	SI, v_arg_index
	MOV 	BX, cur_arg_buff
	MOV 	[BX + SI], DL
	INC 	SI
	MOV 	v_arg_index, SI

	POP 	BX
	POP 	SI

	RET
put_single_char endp

store_as_adress proc
	; Store the next 4 bytes as an adress
	; Used for SRB, AB
	CALL	store_next_byte				; Get next byte (IN DL)
	MOV 	AL, DL						; Set it to AL
	CALL 	store_next_byte				; ELSE: width is word
	MOV 	AH, DL						; Store DL to AH
	MOV 	CL, 4						; size is 4
	CALL 	convert_number
	RET
store_as_adress endp

put_arg_prefix proc
	; Puts the prefix (if any) in front of argument
	; RESULT: v_arg_1 or v_arg_2 (according to cur_arg_buff)
	PUSH 	AX
	PUSH 	BX
	PUSH 	CX
	PUSH 	DX

	MOV 	AX, temp_prefix
	MOV 	BX, offset noReg
	CMP 	AX, BX
	JE 		NO_PREFIX_EXISTS

	MOV 	DX, temp_prefix
	CALL 	store_as_text

	MOV 	DL, ":"
	CALL 	put_single_char

	NO_PREFIX_EXISTS:
		POP 	DX
		POP	 	CX
		POP 	BX
		POP 	AX

		RET
put_arg_prefix endp

arg_checker proc
	PUSH 	AX
	PUSH 	BX
	PUSH 	CX
	PUSH  	DX

	CMP 	BL, arg_ab					; Is arg AB?
	JNE 	NOT_AB

	MOV 	AL, c_arg_2
	CMP 	AL, arg_srb
	JE 		STORE_AB_SRB

	CALL 	put_arg_prefix

	MOV 	DL, "["
	CALL 	put_single_char

	CALL 	store_as_adress			; Format: seg:[adress]

	MOV 	DL, "]"
	CALL 	put_single_char
	JMP 	NOT_POS

	STORE_AB_SRB:
		CALL 	store_as_adress			; Format: adress
		JMP 	NOT_POS

	NOT_AB:
		CMP 	BL, arg_srb					; Is arg SRB?
		JNE 	NOT_SRB

		CALL 	store_as_adress				; Format: adress:

		MOV 	DL, ":"
		CALL 	put_single_char

		JMP 	NOT_POS
	NOT_SRB:								; Is arg IMM?
		CMP 	BL, arg_imm
		JNE 	NOT_IMM

		CALL 	store_as_number
		JMP 	NOT_POS
	NOT_IMM:
		CMP 	BL, arg_imm8_16				; Is arg 1 byte IMM converted to 2 bytes
		JNE 	NOT_IMM8_16

		CALL	store_next_byte				; Get next byte (IN DL)
		MOV 	AX, 0
		MOV 	AL, DL						; Set it to AL

		AND 	DL, 10000000b
		MOV 	CL, 2
		CMP 	DL, 80h
		JNE 	STORE_ARG_IMM8_16
		MOV 	CL, 4
		MOV 	AH, 11111111b

		STORE_ARG_IMM8_16:
			CALL 	convert_number

			JMP 	NOT_POS
	NOT_IMM8_16:
		CMP		BL, arg_rm					; Is arg reg/mem?
		JE 	IS_RM
		JMP NOT_RM

		IS_RM:
			MOV 	CX, 0
			MOV 	BX, a_mod

			CMP 	BX, 3						; Register
			JE 		RM_REG

			CALL 	put_arg_prefix

			MOV 	DL, "["
			CALL 	put_single_char

			CALL 	ident_rm					; Gets adressing method
			CALL 	store_as_text				;Stores (EX: BX+SI)

			MOV 	BX, a_mod

			CMP 	BX, 2						; 1 byte posl
			JE 		RM_2

			CMP 	BX, 1						; 2 byte posl
			JE 		RM_1

			JMP 	NO_RM						; 0 byte posl (or direct)

			RM_REG:
				MOV 	CH, c_width
				CMP 	CH, 1
				JE 		RM_REG_1

				MOV 	BX, offset regRM_w0
				JMP 	RM_REG_0

			RM_REG_1:
				MOV 	BX, offset regRM_w1
			RM_REG_0:
				MOV 	DX, 0
				MOV 	AX, 0
				MOV 	AL, byte ptr a_rm
				MOV 	DL, 2					; Adresai Word dydzio, tad slenkasi po 2 byte
				MUL 	DL

				ADD 	BX, AX
				MOV 	DX, [BX]

				CALL 	store_as_text

				JMP 	RM_REG_EXIT
			RM_2:								; Store 2 bytes as ascii
				MOV 	DL, "+"
				CALL 	put_single_char

				CALL 	store_next_byte
				MOV 	AL, DL

				CALL 	store_next_byte
				MOV 	AH, DL

				MOV 	CL, 4
				CALL 	convert_number

				JMP 	RM_EXIT
			RM_1:								; Store 1 byte as ascii
				CALL 	store_next_byte
				MOV 	AL, DL
				MOV 	BL, AL

				AND 	BL, 10000000b
				CMP 	BL, 80h
				JE	 	SIGN_RM

				MOV 	DL, "+"
				CALL 	put_single_char

				MOV 	AH, 0
				MOV 	CL, 2
				CALL 	convert_number
				JMP 	RM_EXIT
			SIGN_RM:
				MOV 	DL, "-"
				CALL 	put_single_char
				NEG 	AL
				MOV 	CL, 2
				CALL 	convert_number
				JMP 	RM_EXIT

			NO_RM:
				MOV 	BX, a_rm				; If a_rm is 110, direct adress
				CMP 	BX, 6
				JNE 	RM_EXIT

				CALL 	store_next_byte
				MOV 	AL, DL
				CALL 	store_next_byte
				MOV 	AH, DL

				MOV 	CL, 4
				CALL 	convert_number
			RM_EXIT:
				MOV 	DL, "]"					; Close adress bar
				CALL 	put_single_char
			RM_REG_EXIT:
				JMP 	NOT_POS

	NOT_RM:
		CMP 	BL, arg_reg					; Is arg reg?
		JNE 	NOT_REG

		MOV 	AL, c_is_reg

		CMP 	AL, 1
		JE		REG_IN_OPC

		MOV 	AL, c_is_sr

		CMP 	AL, 1
		JE 		SR_IN_ADB

		REG_IN_ADB:
			MOV 	CH, c_width
			CMP 	CH, 1
			JE 		REG_1

			MOV 	BX, offset regRM_w0
			JMP 	REG_0

		REG_1:
			MOV 	BX, offset regRM_w1
		REG_0:
			MOV 	DX, 0
			MOV 	AX, 0
			MOV 	AL, byte ptr a_reg
			MOV 	DL, 2					; Adresai Word dydzio, tad slenkasi po 2 byte
			MUL 	DL

			ADD 	BX, AX
			MOV 	DX, [BX]

			CALL 	store_as_text

			JMP 	NOT_POS 					;TEMP

		REG_IN_OPC:
			MOV 	DX, c_reg_val
			CALL 	store_as_text
			JMP 	NOT_POS

		SR_IN_ADB:
			MOV 	CL, byte ptr a_reg

			CMP 	CL, 0
			JE 		SR_IS_ES

			CMP 	CL, 1
			JE 		SR_IS_CS

			CMP 	CL, 2
			JE 		SR_IS_SS

			CMP 	CL, 3
			JE 		SR_IS_DS

			MOV 	DX, offset opcUnk
			JMP 	SAVE_SR

			SR_IS_DS:
				MOV 	DX, offset regDS
				JMP 	SAVE_SR
			SR_IS_SS:
				MOV 	DX, offset regSS
				JMP 	SAVE_SR
			SR_IS_CS:
				MOV 	DX, offset regCS
				JMP 	SAVE_SR
			SR_IS_ES:
				MOV 	DX, offset regES
			SAVE_SR:
				CALL 	store_as_text

			JMP 	NOT_POS 					;TEMP

	NOT_REG:
		CMP		BL, arg_pos					; Is arg pos
		JNE 	ONE

		CALL	store_next_byte				; Get next byte (IN DL)
		MOV 	AX, 0
		MOV 	AL, DL						; Set it to AL

		MOV 	CL, 2						; Size always 4

		MOV 	CH, c_width					; Store width of argument
		CMP 	CH, 0						; If width is byte
		JE 		STORE_POS					; Store

		CALL 	store_next_byte				; ELSE: width is word
		MOV 	AH, DL						; Store DL to AH
		MOV 	CL, 4
		STORE_POS:
			CMP 	CL, 2
			JE 		SIGNED_STORE_POS
			MOV 	CL, 4
			ADD 	AX, ip_index
			ADD 	AX, temp_ip_add
			CALL 	convert_number
			JMP 	NOT_POS
		SIGNED_STORE_POS:
			MOV 	BL, AL
			AND 	BL, 10000000b
			CMP 	BL, 80h
			JNE 	NO_SIGN_POS

			MOV 	AH, 11111111b
		NO_SIGN_POS:
			MOV 	CL, 4
			ADD 	AX, ip_index
			ADD 	AX, temp_ip_add
			CALL 	convert_number
			JMP 	NOT_POS

	ONE:
		CMP		BL, arg_one					; Is arg one
		JNE 	NOT_POS

		MOV 	AL, 1
		MOV 	CL, 1
		CALL 	convert_number
		JMP 	NOT_POS

	NOT_POS:
		POP 	DX
		POP 	CX
		POP 	BX
		POP 	AX

		RET
arg_checker endp

set_extra_ident proc
	; BX: Adress to appropriate identification array
	MOV 	AX, 0
	MOV 	AL, byte ptr a_reg		; Get a_reg value
	MOV 	DL, 2
	MUL 	DL						; Multiply by two (Adresses are 2 bytes)
	ADD 	BX, AX					; Add poslinkis
	MOV 	BX, [BX]				; Get new adress from array of adresses
	MOV 	c_opName, BX			; Store adress in c_opName
	RET
set_extra_ident endp

extra_identify proc
	; Goes through all possible extra identities and assigns new c_opName
	; RESULT: c_opName
	PUSH 	AX
	PUSH 	BX
	PUSH 	CX
	PUSH 	DX

	MOV 	CX, offset opcx80
	MOV 	BX, c_opName
	CMP		BX, CX
	JNE 	NOT_opcx80

	MOV 	BX, offset identifyx80
	CALL 	set_extra_ident
	JMP 	NOT_opcxFF

	NOT_opcx80:
		MOV 	CX, offset opcxF6
		MOV 	BX, c_opName
		CMP		BX, CX
		JNE 	NOT_opcxF6

		MOV 	BX, offset identifyxF6
		CALL 	set_extra_ident
		JMP 	NOT_opcxFF

	NOT_opcxF6:
		MOV 	CX, offset opcxFE
		MOV 	BX, c_opName
		CMP		BX, CX
		JNE 	NOT_opcxFE

		MOV 	BX, offset identifyxFE
		CALL 	set_extra_ident
		JMP 	NOT_opcxFF

	NOT_opcxFE:
		MOV 	CX, offset opcxFF
		MOV 	BX, c_opName
		CMP		BX, CX
		JNE 	NOT_opcxD0

		MOV 	BX, offset identifyxFF
		CALL 	set_extra_ident
		JMP 	NOT_opcxFF
	NOT_opcxD0:
		MOV 	CX, offset opcxD0
		MOV 	BX, c_opName
		CMP		BX, CX
		JNE 	NOT_opcxFF

		MOV 	BX, offset identifyxD0
		CALL 	set_extra_ident
	NOT_opcxFF:
		POP 	DX
		POP 	CX
		POP 	BX
		POP 	AX

		RET
extra_identify endp

analyze_adress_byte proc
	; Stores MOD, REG, RM in appropriate variables from adress byte
	; RESULT: a_mod, a_reg, a_rm
	PUSH 	AX
	PUSH 	BX
	PUSH 	CX
	PUSH 	DX

	CALL 	store_next_byte

	PUSH 	DX
	MOV 	BX, 11000000b
	AND 	DX, BX

	ROR 	DX, 6			; Shift right 6 times

	MOV 	a_mod, DX		; Save 000000xxb
	POP 	DX

	PUSH 	DX
	MOV 	BX, 00111000b
	AND 	DX, BX

	ROR 	DX, 3			; Shift right 3 times

	MOV 	a_reg, DX		; Save 00000xxxb
	POP 	DX

	MOV 	BX, 00000111b
	AND 	DX, BX
	MOV 	a_rm, DX		; Save 00000xxxb

	POP 	DX
	POP 	CX
	POP 	BX
	POP 	AX

	RET
analyze_adress_byte endp

clear_temp_bytes proc
	;Clear the read bytes buffer
	PUSH 	AX
	PUSH 	BX
	PUSH 	CX
	PUSH 	DX

	MOV 	CX, 0
	MOV 	temp_b_index, CX
	MOV 	DX, " "
	MOV 	BX, offset temp_bytes

	CLEAR_LOOP:
		MOV 	[BX], DX
		ADD 	BX, 1
		CMP 	CX, 24
		JE  	EXIT_CLEAR
		INC 	CX
		JMP CLEAR_LOOP

	EXIT_CLEAR:
		POP 	DX
		POP 	CX
		POP 	BX
		POP 	AX

		RET
clear_temp_bytes endp

write_arg proc
	; DX adress to write
	; v_arg_1 or v_arg_2
	; RESULT: arg written in file
	MOV 	AX, 0
	MOV 	BX, DX
	ARG1LOOP:
		INC 	AX
		INC  	BX
		MOV 	CL, byte ptr [BX]
		CMP		CL, "$"
	JNE 	ARG1LOOP

	MOV 	CX, AX					; Write result
	MOV 	BX, out_handle
	MOV 	AX, 4000h					; Write
	INT 	21h

	ARG2LOOP:
		MOV 	BX, DX
		MOV 	AL, "$"
		MOV 	[BX], AL
		INC 	DX

		MOV 	BX, DX
		MOV 	CL, byte ptr [BX]
		CMP		CL, "$"
	JNE 	ARG2LOOP
	RET
write_arg endp

write_single proc
	; DX is buffer for symbol writing
	; RESULT: updated output file
	MOV 	CX, 1					; Write result
	MOV 	BX, out_handle
	MOV 	AX, 4000h				; Write
	INT 	21h
	RET
write_single endp

write_multiple proc
	; CX is bytes to write
	; DX is adress of buffer
	; RESULT: updated output file
	MOV 	BX, out_handle
	MOV 	AX, 4000h				; Write
	INT 	21h
	RET
write_multiple endp

write_proc proc
	; Writes analyzed command and resets all buffers for further work
	PUSH 	AX
	PUSH 	BX
	PUSH 	CX
	PUSH 	DX

	; IP COUNTER PRINT
	MOV 	ip_arr_index, 0

	MOV 	BX, offset ip_value
	MOV 	AX, offset ip_arr_index
	MOV 	needs_convert, BX			; The converted value buffer (Adress)
	MOV 	counter_convert, AX			; The index for output buffer (Adress)
	MOV 	CL, 4						; Convert 4 bytes
	MOV 	AX, ip_index				; The value that needs convertsion

	CALL 	number_to_ascii				; Convert value

	MOV 	AX, temp_ip_add
	ADD 	ip_index, AX				; Add accumulated ip value
	MOV 	temp_ip_add, 0				; Zero out the acuumulation

	MOV 	CX, 4					; Write 4 bytes (of IP)
	MOV 	DX, offset ip_value		; Adress of IP ascii buffer
	CALL 	write_multiple			; Write to file

	MOV 	DX, offset doublepoint	; Write ":"
	CALL 	write_single

	MOV 	CX, 6
	MOV 	DX, offset space
	CALL 	write_multiple			; Write to file
	;IP COUNTER PRINT END

	;BYTE PRINT
	MOV 	CX, 25					; Write result
	MOV 	DX, offset temp_bytes
	CALL 	write_multiple			; Write to file

	CALL 	clear_temp_bytes
	;BYTE PRINT END

	;Opertation code NAME print
	MOV 	DX, c_opName
	PUSH 	DX						; SAVE ORIGINAL c_opName adress

	MOV 	AX, 0					; Register for counting opName length
	NAMELOOP:
		INC 	AX					; No "$" found yet

		MOV 	BX, c_opName
		ADD 	BX, AX				; Offset name adress by AX

		MOV 	CL, [BX]			; Check if next char is "$"
		CMP		CL, "$"
	JNE 	NAMELOOP				; If not, loop

	POP 	DX
	PUSH 	AX						; Save the length of c_opName

	MOV 	c_opName, DX			; Reset the c_opName

	MOV 	CX, AX					; Write result
	CALL 	write_multiple			; Write to file

	POP 	AX						; Get c_opName length

	MOV 	CX, 0
	CMP 	AL, 10					; If opName is larger than 10 spaces
	JGE 	WRITE_SPACES			; No spaces needed

	MOV 	CL, 10					; Else
	SUB 	CL, AL					; Print spaces: 10 - len
	MOV 	CH, 0

	WRITE_SPACES:
	MOV 	DX, offset space
	CALL 	write_multiple			; Write " " to file
	;Opertation code NAME print END

	MOV 	CX, offset opcUnk
	CMP 	CX, c_opName
	JNE 	CHECKS					; If not unknown, needs further arguments
	JMP 	QUIT_WRITING			; Else, quit write

	CHECKS:
	;CHECK FOR ADRESS
	MOV 	AL, c_arg_2
	CMP 	AL, arg_srb
	JNE 	CHECK_RM_IMM_CASE

	MOV 	DX, offset v_arg_2
	CALL 	write_arg
	MOV 	DX, offset v_arg_1
	CALL 	write_arg
	JMP 	QUIT_WRITING
	;CHECK FOR ADRESS END

	;CHECK RM IMM CASE
	CHECK_RM_IMM_CASE:
		MOV 	AX, c_reg_val			; Get register value
		CMP 	AX, needs_far			; ONLY true when FF
		JE 		NEED_FAR
	CHECK_RM_IMM_CASE_2:
		MOV 	AX, a_mod				; If mod is 3, it is not memory
		CMP 	AX, 3
		JE 		WRITE_NORMAL

		MOV  	AL, c_arg_1				; If not memory, normal write
		CMP 	AL, arg_rm
		JNE 	WRITE_NORMAL

		MOV 	AL, c_arg_2				; If immediate, need byte ptr
		CMP 	AL, arg_imm
		JE	 	WORD_OR_BYTE

		MOV 	AL, c_arg_2				; If only memory, need to override
		CMP 	AL, arg_none
		JE		WORD_OR_BYTE

		JMP 	WRITE_NORMAL 			; If none of these, normal write

		ONLY_BYTE:
			MOV 	CX, 9					; Write "byte ptr "
			MOV 	DX, offset byte_ptr
			CALL 	write_multiple			; Write to file
			JMP 	WRITE_NORMAL

		WORD_OR_BYTE:
			MOV 	AL, c_width			; If size is byte, byte ptr
			CMP		AL, w_byte
			JE 		ONLY_BYTE

			MOV 	CX, 9					; Write "word ptr "
			MOV 	DX, offset word_ptr
			CALL 	write_multiple			; Write to file
			JMP 	WRITE_NORMAL
	;CHECK RM IMM CASE END

	;CHECK FAR CASE
	NEED_FAR:
		MOV 	AX, a_reg
		CMP 	AX, 3						; Far call 011
		JE 		IS_FAR

		MOV 	AX, a_reg
		CMP 	AX, 5						; Far jmp 101
		JE 		IS_FAR

		MOV 	AX, a_reg
		CMP 	AX, 2						; Inner indirect call 010 (no ptr needed)
		JE 		WRITE_NORMAL

		MOV 	AX, a_reg
		CMP 	AX, 4						; Inner indirect jmp 100
		JE 		WRITE_NORMAL

		JMP 	CHECK_RM_IMM_CASE_2			; Else, check for ptr
	INVALID:
		MOV 	CX, 14
		MOV 	DX, offset invalid_msg
		CALL 	write_multiple
		JMP 	WRITE_NORMAL

	IS_FAR:
		MOV 	AX, a_mod					; Cannot have reg in far call/jump
		CMP 	AX, 3
		JE 		INVALID

		MOV 	CX, 4
		MOV 	DX, offset far_msg
		CALL 	write_multiple
	;CHECK FAR CASE END

	WRITE_NORMAL:
		MOV 	DX, offset v_arg_1			; If no arguments exists, dont write
		MOV 	BX, DX
		MOV 	CL, byte ptr [BX]
		CMP		CL, "$"
		JE 		QUIT_WRITING

		CALL 	write_arg					; W

		MOV 	DX, offset v_arg_2			; If 2nd argument doesnt exist, dont write
		MOV 	BX, DX
		MOV 	CL, byte ptr [BX]
		CMP		CL, "$"
		JE 		QUIT_WRITING

		MOV 	DX, offset point
		CALL 	write_single

		MOV 	DX, offset space
		CALL 	write_single

		MOV 	DX, offset v_arg_2
		CALL 	write_arg

  	QUIT_WRITING:
		MOV 	CX, 2					; Write result
		MOV 	DX, offset new_line
		CALL 	write_multiple			; Write to file

		POP 	DX
		POP 	CX
		POP 	BX
		POP 	AX

		RET
write_proc endp

check_read proc
	; Check if input needs to be replenished
	; RESULT: nothing or replenished input_buff
	PUSH 	AX
	MOV 	AX, [bytes_read]
	CMP 	AX, 0
	JLE 	READ
	POP 	AX
	RET

	READ:
		CALL 	read_input
		POP 	AX
		RET
check_read endp

read_input proc
	; Updates bytes_read with new value. Does not change registers
	PUSH 	AX
	PUSH 	BX
	PUSH 	CX
	PUSH 	DX

	MOV 	BX, in_handle
	MOV 	CX, 255 				; Read 255 byte
	MOV 	DX, OFFSET input_buff
	MOV 	AX, 3F00h
	INT		21h

	MOV 	[bytes_read], AX
	MOV 	AX, 0
	MOV 	[temp_index], AX

	POP 	DX
	POP 	CX
	POP 	BX
	POP 	AX

	CALL 	check_carry				; Check if successful

	RET
read_input endp

store_next_byte proc
	; Reads and stores next byte in DL
	PUSH 	AX
	PUSH 	BX
	PUSH 	CX

	CALL 	check_read				; Check if input needs repleneshing has to be read

	MOV 	BX, temp_index			; Set bx value to temp_index
	MOV 	DH, 0					; Set DH to 0
	MOV 	DL, [input_buff + BX]	; Get from input buffer
	INC 	BX
	MOV 	[temp_index], BX		; Increase temp_index

	MOV 	CX, [bytes_read]		; Decrease the bytes_read
	DEC 	CX
	MOV 	[bytes_read], CX


	; Store read byte in temp_bytes for printing
	MOV 	BX, offset temp_bytes
	MOV 	AX, offset temp_b_index
	MOV 	needs_convert, BX
	MOV 	counter_convert, AX
	MOV 	CL, 2
	MOV 	AH, 0
	MOV 	AL, DL

	CALL 	number_to_ascii
	INC 	temp_b_index		; Increase the temp_b_index (to add a space between them)

	INC 	temp_ip_add			; Increase IP

	POP 	CX
	POP 	BX
	POP 	AX

	RET
store_next_byte endp

number_to_ascii proc
	; Convert read byte to ascii and store in temp_bytes
	; CL is number of chars
	; AX is adress to value
	; BX is adress to buffer of writing
	; RESULT: [BX] <- ASCII number

	PUSH 	AX
	PUSH 	BX
	PUSH 	CX
	PUSH 	DX

	MOV 	CH, CL

	CONV:
		CMP		CL, 0
		JE		FIN_CONV
		DEC 	CL

		MOV 	BX, 16
		MOV 	DX, 0
		DIV 	BX

		MOV 	BX, offset hex
		ADD 	BX, DX
		MOV 	DL, [BX]
		MOV 	DH, 0

		PUSH 	DX
	JMP CONV

	FIN_CONV:
		CMP 	CH, 0
		JE		FIN
		DEC 	CH

		POP 	DX

		MOV 	BX, needs_convert
		MOV 	SI, counter_convert

		ADD 	BX, [SI]
		MOV 	[BX], DL

		INC 	word ptr [SI]
	JMP FIN_CONV

	FIN:
		POP 	DX
		POP 	CX
		POP 	BX
		POP 	AX

		RET
number_to_ascii endp

recognize_byte proc
	; Find appropriate byte by value in DL
	; Takes size of the structure, multiplies it by DL to get offset
	; Offsets to correct location, gets the bytes
	PUSH 	AX
	PUSH 	BX

	MOV 	AL, size opcInfo 			; Gets the syze in bytes of the opcInfo struct
	MUL 	DL							; Multiplies that by stored byte

	MOV 	BX, offset [opcInfoStart]	; Offsets to start of the array
	INC 	BX							; Skip the first byte
	ADD 	BX, AX

	MOV 	AX, [BX].s_opName			; All the storing
	MOV 	[c_opName], AX

	MOV 	AL, [BX].s_abyte
	MOV 	[c_abyte], AL

	MOV 	AL, [BX].s_width
	MOV 	[c_width], AL

	MOV 	AL, [BX].s_is_reg
	MOV 	[c_is_reg], AL

	MOV 	AX, [BX].s_reg_val
	MOV 	[c_reg_val], AX

	MOV 	AL, [BX].s_arg_1
	MOV 	[c_arg_1], AL

	MOV 	AL, [BX].s_arg_2
	MOV 	[c_arg_2], AL

	MOV 	AL, [BX].s_is_sr
	MOV 	[c_is_sr], AL

	POP 	BX
	POP 	AX

	RET
recognize_byte endp

check_carry proc
	JC 		STOP_PROGRAM			; If carry flag is set, stop
	RET								; Else ret

	STOP_PROGRAM:
		MOV 	DX, offset cant_open 	; Output cant open msg
		MOV 	AH, 09
		INT 	21h

		MOV 	DX, OFFSET arg_msg		; Output "/?"
		MOV 	AH, 09
		INT 	21h

		MOV 	AX, 4C00H				; Terminate
		INT 	21h
check_carry endp

end start
