w_byte 		EQU 0
w_word 		EQU 1

no_reg		EQU 0
reg 		EQU 1
reg_aby		EQU 2
needs_far 	EQU 3

no_prefix	EQU 0
prefix 		EQU 1

no_abyte	EQU 0
abyte		EQU 1

no_sr		EQU 0
sr 			EQU 1

sr_opc		EQU 0
sr_pos		EQU 1

arg_imm 	EQU 0
arg_imm8_16	EQU 1
arg_reg 	EQU 2
arg_rm		EQU 3
arg_pos		EQU 4
arg_ab		EQU 5
arg_srb		EQU 6
arg_none	EQU 7
arg_rm_adr 	EQU 8
arg_one 	EQU 9

rm_000_00	DB "BX+SI$"
rm_001_00	DB "BX+DI$"
rm_010_00	DB "BP+SI$"
rm_011_00	DB "BP+DI$"
rm_100_00	DB "SI$"
rm_101_00	DB "DI$"
rm_110_00	DB "$"
rm_111_00	Db "BX$"

rm_000_01	DB "BX+SI$"
rm_001_01	DB "BX+DI$"
rm_010_01	DB "BP+SI$"
rm_011_01	DB "BP+DI$"
rm_100_01	DB "SI$"
rm_101_01	DB "DI$"
rm_110_01	DB "BP$"
rm_111_01	Db "BX$"


noReg 		DB "$$$"
regES		DB "ES$"		;26
regCS		DB "CS$"		;2E
regSS		DB "SS$"		;36
regDS		DB "DS$"		;3E

regAX		DB "AX$"
regBX		DB "BX$"
regCX		DB "CX$"
regDX		DB "DX$"
regAL		DB "AL$"
regAH		DB "AH$"
regBL		DB "BL$"
regBH		DB "BH$"
regCL		DB "CL$"
regCH		DB "CH$"
regDL		DB "DL$"
regDH		DB "DH$"

regSP		DB "SP$"
regBP		DB "BP$"
regSI		DB "SI$"
regDI		DB "DI$"

opcAdd 		DB "ADD$"
opcMov 		DB "MOV$"
opcPush 	DB "PUSH$"
opcPop 		DB "POP$"
opcInc		DB "INC$"
opcSub	 	DB "SUB$"
opcDec 		DB "DEC$"
opcCmp 		DB "CMP$"
opcMul 		DB "MUL$"
opcDiv 		DB "DIV$"
opcJmp 		DB "JMP$"
opcCall 	DB "CALL$"
opcRetf  	DB "RETF$"
opcRetn  	DB "RETN$"
opcJa 		DB "JA$"		;opcJnbe	DB "JNBE$"
opcJb 		DB "JB$"		;opcJnae 	DB "JNAE$" ;opcJc		DB "JC$"
opcJbe		DB "JBE$"		;opcJna		DB "JNA$"
opcJcxz 	DB "JCXZ$"
opcJe 		DB "JE$" 		;opcJZ 		DB "JZ$"
opcJg 		DB "JG$"		;opcJnle 	DB "JNLE$"
opcJge 		DB "JGE$"		;opcJnl 	DB "JNL$"
opcJl		DB "JL$"		;opcJnge 	DB "JNGE$"
opcJle		DB "JLE$"		;opcJng 	DB "JNG$"
opcJnb 		DB "JNB$" 		;opcJae		DB "JAE$" ;opcJnc		DB "JNC$"
opcJne		DB "JNE$"		;opcJnz		DB "JNZ$"
opcJno 		DB "JNO$"
opcJnp 		DB "JNP$"		;opcJpo		DB "JPO$"
opcJns 		DB "JNS$"
opcJo 		DB "JO$"
opcJp		DB "JP$"		;opcJpe 		DB "JPE$"
opcJs		DB "JS$"
opcInt 		DB "INT$"
opcLoop		DB "LOOP$"
opcUnk		DB "UNKNOWN$"
opcx80		DB "80$"
opcxF6		DB "F6$"
opcxFE		DB "FE$"
opcxFF		DB "FF$"
opcxD0 		DB "D0$"
opcPrefix 	DB "Prefix$"

opcOr 		DB "OR$"
opcAdc		DB "ADC$"
opcSbb 		DB "SBB$"
opcAnd 		DB "AND$"
opcDaa 		DB "DAA$"
opcDas		DB "DAS$"
opcXor 		DB "XOR$"
opcAaa		DB "AAA$"
opcAas 		DB "AAS$"
opcTest		DB "TEST$"
opcXchg 	DB "XCHG$"
opcXchgAX 	DB "XCHG      AX, $"
opcLea 		DB "LEA$"
opcCbw 		DB "CBW$"
opcCwd	 	DB "CWD$"
opcWait 	DB "WAIT$"
opcPushf 	DB "PUSHF$"
opcPopf 	DB "POPF$"
opcSahf 	DB "SAHF$"
opcLahf 	DB "LAHF$"
opcMovsb 	DB "MOVSB$"
opcMovsw 	DB "MOVSW$"
opcCmpsb 	DB "CMPSB$"
opcCmpsw 	DB "CMPSW$"
opcStosb 	DB "STOSB$"
opcStosw 	DB "STOSW$"
opcLodsb 	DB "LODSB$"
opcLodsw 	DB "LODSW$"
opcScasb 	DB "SCASB$"
opcScasw 	DB "SCASW$"
opcLes 		DB "LES$"
opcLds 		DB "LDS$"
opcInt3 	DB "INT       3$"
opcInto 	DB "INTO$"
opcIRet 	DB "IRET$"
opcXlat 	DB "XLAT$"
opcLoopne 	DB "LOOPNE$"
opcLoope 	DB "LOOPE$"
opcLock 	DB "LOCK$"
opcRepnz 	DB "REPNZ$"
opcRepz 	DB "REPZ$"
opcHlt 		DB "HLT$"
opcCmc 		DB "CMC$"
opcNot 		DB "NOT$"
opcNeg 		DB "NEG$"
opcIMul 	DB "IMUL$"
opcIDiv 	DB "IDIV$"
opcClc 		DB "CLC$"
opcStc 		DB "STC$"
opcCli 		DB "CLI$"
opcSti 		DB "STI$"
opcCld 		DB "CLD$"
opcStd 		DB "STD$"
opcIn		DB "IN$"
opcOut 		DB "OUT$"
opcRol 		DB "ROL$"

opcInfoStart 		DB 0
	; name, adress_byte, width, is_reg, reg, arg1_type, arg2_type, segment_reg_exists
	;ADD
	opcInfo<opcAdd, abyte, w_byte, reg_aby, noReg, arg_rm, arg_reg, no_sr>				; 00
	opcInfo<opcAdd, abyte, w_word, reg_aby, noReg, arg_rm, arg_reg, no_sr>				; 01
	opcInfo<opcAdd, abyte, w_byte, reg_aby, noReg, arg_reg, arg_rm, no_sr>				; 02
	opcInfo<opcAdd, abyte, w_word, reg_aby, noReg, arg_reg, arg_rm, no_sr>				; 03
	opcInfo<opcAdd, no_abyte, w_byte, reg, regAL, arg_reg, arg_imm, no_sr>				; 04
	opcInfo<opcAdd, no_abyte, w_word, reg, regAX, arg_reg, arg_imm, no_sr>				; 05
	;PUSH/POP seg reg
	opcInfo<opcPush, no_abyte, w_word, reg, regES, arg_reg, arg_none, sr>				; 06
	opcInfo<opcPop, no_abyte, w_word, reg, regES, arg_reg, arg_none, sr>				; 07
	;OR
	opcInfo<opcOr, abyte, w_byte, reg_aby, noReg, arg_rm, arg_reg, no_sr>				; 08
	opcInfo<opcOr, abyte, w_word, reg_aby, noReg, arg_rm, arg_reg, no_sr>				; 09
	opcInfo<opcOr, abyte, w_byte, reg_aby, noReg, arg_reg, arg_rm, no_sr>				; 0A
	opcInfo<opcOr, abyte, w_word, reg_aby, noReg, arg_reg, arg_rm, no_sr>				; 0B
	opcInfo<opcOr, no_abyte, w_byte, reg, regAL, arg_reg, arg_imm, no_sr>				; 0C
	opcInfo<opcOr, no_abyte, w_word, reg, regAX, arg_reg, arg_imm, no_sr>				; 0D
	;PUSH/POP seg reg
	opcInfo<opcPush, no_abyte, w_word, reg, regCS, arg_reg, arg_none, sr>				; 0E
	opcInfo<opcPop, no_abyte, w_word, reg, regCS, arg_reg, arg_none, sr>				; 0F
	;ADC
	opcInfo<opcAdc, abyte, w_byte, reg_aby, noReg, arg_rm, arg_reg, no_sr>				; 10
	opcInfo<opcAdc, abyte, w_word, reg_aby, noReg, arg_rm, arg_reg, no_sr>				; 11
	opcInfo<opcAdc, abyte, w_byte, reg_aby, noReg, arg_reg, arg_rm, no_sr>				; 12
	opcInfo<opcAdc, abyte, w_word, reg_aby, noReg, arg_reg, arg_rm, no_sr>				; 13
	opcInfo<opcAdc, no_abyte, w_byte, reg, regAL, arg_reg, arg_imm, no_sr>				; 14
	opcInfo<opcAdc, no_abyte, w_word, reg, regAX, arg_reg, arg_imm, no_sr>				; 15
	;PUSH/POP seg reg
	opcInfo<opcPush, no_abyte, w_word, reg, regSS, arg_reg, arg_none, sr>				; 16
	opcInfo<opcPop, no_abyte, w_word, reg, regSS, arg_reg, arg_none, sr>				; 17
	;SBB
	opcInfo<opcSbb, abyte, w_byte, reg_aby, noReg, arg_rm, arg_reg, no_sr>				; 18
	opcInfo<opcSbb, abyte, w_word, reg_aby, noReg, arg_rm, arg_reg, no_sr>				; 19
	opcInfo<opcSbb, abyte, w_byte, reg_aby, noReg, arg_reg, arg_rm, no_sr>				; 1A
	opcInfo<opcSbb, abyte, w_word, reg_aby, noReg, arg_reg, arg_rm, no_sr>				; 1B
	opcInfo<opcSbb, no_abyte, w_byte, reg, regAL, arg_reg, arg_imm, no_sr>				; 1C
	opcInfo<opcSbb, no_abyte, w_word, reg, regAX, arg_reg, arg_imm, no_sr>				; 1D
	;PUSH/POP seg reg
	opcInfo<opcPush, no_abyte, w_word, reg, regDS, arg_reg, arg_none, sr>				; 1E
	opcInfo<opcPop, no_abyte, w_word, reg, regDS, arg_reg, arg_none, sr>				; 1F
	;AND
	opcInfo<opcAnd, abyte, w_byte, reg_aby, noReg, arg_rm, arg_reg, no_sr>				; 20
	opcInfo<opcAnd, abyte, w_word, reg_aby, noReg, arg_rm, arg_reg, no_sr>				; 21
	opcInfo<opcAnd, abyte, w_byte, reg_aby, noReg, arg_reg, arg_rm, no_sr>				; 22
	opcInfo<opcAnd, abyte, w_word, reg_aby, noReg, arg_reg, arg_rm, no_sr>				; 23
	opcInfo<opcAnd, no_abyte, w_byte, reg, regAL, arg_reg, arg_imm, no_sr>				; 24
	opcInfo<opcAnd, no_abyte, w_word, reg, regAX, arg_reg, arg_imm, no_sr>				; 25
	;Prefix
	opcInfo<opcPrefix, no_abyte, w_byte, reg, regES, arg_none, arg_none, no_sr>			; 26
	;DAA
	opcInfo<opcDaa, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>			; 27
	;Subs
	opcInfo<opcSub, abyte, w_byte, reg_aby, noReg, arg_rm, arg_reg, no_sr>				; 28
	opcInfo<opcSub, abyte, w_word, reg_aby, noReg, arg_rm, arg_reg, no_sr>				; 29
	opcInfo<opcSub, abyte, w_byte, reg_aby, noReg, arg_reg, arg_rm, no_sr>				; 2A
	opcInfo<opcSub, abyte, w_word, reg_aby, noReg, arg_reg, arg_rm, no_sr>				; 2B
	opcInfo<opcSub, no_abyte, w_byte, reg, regAL, arg_reg, arg_imm, no_sr>				; 2C
	opcInfo<opcSub, no_abyte, w_word, reg, regAX, arg_reg, arg_imm, no_sr>				; 2D
	;Prefix
	opcInfo<opcPrefix, no_abyte, w_byte, reg, regCS, arg_none, arg_none, no_sr>			; 2E
	;DAS
	opcInfo<opcDas, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>			; 2F
	;XOR
	opcInfo<opcXor, abyte, w_byte, reg_aby, noReg, arg_rm, arg_reg, no_sr>				; 30
	opcInfo<opcXor, abyte, w_word, reg_aby, noReg, arg_rm, arg_reg, no_sr>				; 31
	opcInfo<opcXor, abyte, w_byte, reg_aby, noReg, arg_reg, arg_rm, no_sr>				; 32
	opcInfo<opcXor, abyte, w_word, reg_aby, noReg, arg_reg, arg_rm, no_sr>				; 33
	opcInfo<opcXor, no_abyte, w_byte, reg, regAL, arg_reg, arg_imm, no_sr>				; 34
	opcInfo<opcXor, no_abyte, w_word, reg, regAX, arg_reg, arg_imm, no_sr>				; 35
	;Prefix
	opcInfo<opcPrefix, no_abyte, w_byte, reg, regSS, arg_none, arg_none, no_sr>			; 36
	;AAA
	opcInfo<opcAaa, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>			; 37
	;Cmps
	opcInfo<opcCmp, abyte, w_byte, reg_aby, noReg, arg_rm, arg_reg, no_sr>				; 38
	opcInfo<opcCmp, abyte, w_word, reg_aby, noReg, arg_rm, arg_reg, no_sr>				; 39
	opcInfo<opcCmp, abyte, w_byte, reg_aby, noReg, arg_reg, arg_rm, no_sr>				; 3A
	opcInfo<opcCmp, abyte, w_word, reg_aby, noReg, arg_reg, arg_rm, no_sr>				; 3B
	opcInfo<opcCmp, no_abyte, w_byte, reg, regAL, arg_reg, arg_imm, no_sr>				; 3C
	opcInfo<opcCmp, no_abyte, w_word, reg, regAX, arg_reg, arg_imm, no_sr>				; 3D
	;UNK
	opcInfo<opcPrefix, no_abyte, w_byte, reg, regDS, arg_none, arg_none, no_sr>			; 3E
	;AAS
	opcInfo<opcAas, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>			; 3F
	;INCs
	opcInfo<opcInc, no_abyte, w_word, reg, regAX, arg_reg, arg_none, no_sr>				; 40
	opcInfo<opcInc, no_abyte, w_word, reg, regCX, arg_reg, arg_none, no_sr>				; 41
	opcInfo<opcInc, no_abyte, w_word, reg, regDX, arg_reg, arg_none, no_sr>				; 42
	opcInfo<opcInc, no_abyte, w_word, reg, regBX, arg_reg, arg_none, no_sr>				; 43
	opcInfo<opcInc, no_abyte, w_word, reg, regSP, arg_reg, arg_none, no_sr>				; 44
	opcInfo<opcInc, no_abyte, w_word, reg, regBP, arg_reg, arg_none, no_sr>				; 45
	opcInfo<opcInc, no_abyte, w_word, reg, regSI, arg_reg, arg_none, no_sr>				; 46
	opcInfo<opcInc, no_abyte, w_word, reg, regDI, arg_reg, arg_none, no_sr>				; 47
	;DECs
	opcInfo<opcDec, no_abyte, w_word, reg, regAX, arg_reg, arg_none, no_sr>				; 48
	opcInfo<opcDec, no_abyte, w_word, reg, regCX, arg_reg, arg_none, no_sr>				; 49
	opcInfo<opcDec, no_abyte, w_word, reg, regDX, arg_reg, arg_none, no_sr>				; 4A
	opcInfo<opcDec, no_abyte, w_word, reg, regBX, arg_reg, arg_none, no_sr>				; 4B
	opcInfo<opcDec, no_abyte, w_word, reg, regSP, arg_reg, arg_none, no_sr>				; 4C
	opcInfo<opcDec, no_abyte, w_word, reg, regBP, arg_reg, arg_none, no_sr>				; 4D
	opcInfo<opcDec, no_abyte, w_word, reg, regSI, arg_reg, arg_none, no_sr>				; 4E
	opcInfo<opcDec, no_abyte, w_word, reg, regDI, arg_reg, arg_none, no_sr>				; 4F
	;PUSHES
	opcInfo<opcPush, no_abyte, w_word, reg, regAX, arg_reg, arg_none, no_sr>			; 50
	opcInfo<opcPush, no_abyte, w_word, reg, regCX, arg_reg, arg_none, no_sr>			; 51
	opcInfo<opcPush, no_abyte, w_word, reg, regDX, arg_reg, arg_none, no_sr>			; 52
	opcInfo<opcPush, no_abyte, w_word, reg, regBX, arg_reg, arg_none, no_sr>			; 53
	opcInfo<opcPush, no_abyte, w_word, reg, regSP, arg_reg, arg_none, no_sr>			; 54
	opcInfo<opcPush, no_abyte, w_word, reg, regBP, arg_reg, arg_none, no_sr>			; 55
	opcInfo<opcPush, no_abyte, w_word, reg, regSI, arg_reg, arg_none, no_sr>			; 56
	opcInfo<opcPush, no_abyte, w_word, reg, regDI, arg_reg, arg_none, no_sr>			; 57
	;POPS
	opcInfo<opcPop, no_abyte, w_word, reg, regAX, arg_reg, arg_none, no_sr>				; 58
	opcInfo<opcPop, no_abyte, w_word, reg, regCX, arg_reg, arg_none, no_sr>				; 59
	opcInfo<opcPop, no_abyte, w_word, reg, regDX, arg_reg, arg_none, no_sr>				; 5A
	opcInfo<opcPop, no_abyte, w_word, reg, regBX, arg_reg, arg_none, no_sr>				; 5B
	opcInfo<opcPop, no_abyte, w_word, reg, regSP, arg_reg, arg_none, no_sr>				; 5C
	opcInfo<opcPop, no_abyte, w_word, reg, regBP, arg_reg, arg_none, no_sr>				; 5D
	opcInfo<opcPop, no_abyte, w_word, reg, regSI, arg_reg, arg_none, no_sr>				; 5E
	opcInfo<opcPop, no_abyte, w_word, reg, regDI, arg_reg, arg_none, no_sr>				; 5F
	;UNK
	opcInfo<opcUnk, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>			; 60
	opcInfo<opcUnk, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>			; 61
	opcInfo<opcUnk, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>			; 62
	opcInfo<opcUnk, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>			; 63
	opcInfo<opcUnk, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>			; 64
	opcInfo<opcUnk, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>			; 65
	opcInfo<opcUnk, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>			; 66
	opcInfo<opcUnk, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>			; 67
	opcInfo<opcUnk, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>			; 68
	opcInfo<opcUnk, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>			; 69
	opcInfo<opcUnk, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>			; 6A
	opcInfo<opcUnk, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>			; 6B
	opcInfo<opcUnk, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>			; 6C
	opcInfo<opcUnk, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>			; 6D
	opcInfo<opcUnk, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>			; 6E
	opcInfo<opcUnk, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>			; 6F
	;JUMPS
	opcInfo<opcJo, no_abyte, w_byte, no_reg, noReg, arg_pos, arg_none, no_sr>			; 70
	opcInfo<opcJno, no_abyte, w_byte, no_reg, noReg, arg_pos, arg_none, no_sr>			; 71
	opcInfo<opcJb, no_abyte, w_byte, no_reg, noReg, arg_pos, arg_none, no_sr>			; 72
	opcInfo<opcJnb, no_abyte, w_byte, no_reg, noReg, arg_pos, arg_none, no_sr>			; 73
	opcInfo<opcJe, no_abyte, w_byte, no_reg, noReg, arg_pos, arg_none, no_sr>			; 74
	opcInfo<opcJne, no_abyte, w_byte, no_reg, noReg, arg_pos, arg_none, no_sr>			; 75
	opcInfo<opcJbe, no_abyte, w_byte, no_reg, noReg, arg_pos, arg_none, no_sr>			; 76
	opcInfo<opcJa, no_abyte, w_byte, no_reg, noReg, arg_pos, arg_none, no_sr>			; 77
	opcInfo<opcJs, no_abyte, w_byte, no_reg, noReg, arg_pos, arg_none, no_sr>			; 78
	opcInfo<opcJns, no_abyte, w_byte, no_reg, noReg, arg_pos, arg_none, no_sr>			; 79
	opcInfo<opcJp, no_abyte, w_byte, no_reg, noReg, arg_pos, arg_none, no_sr>			; 7A
	opcInfo<opcJnp, no_abyte, w_byte, no_reg, noReg, arg_pos, arg_none, no_sr>			; 7B
	opcInfo<opcJl, no_abyte, w_byte, no_reg, noReg, arg_pos, arg_none, no_sr>			; 7C
	opcInfo<opcJge, no_abyte, w_byte, no_reg, noReg, arg_pos, arg_none, no_sr>			; 7D
	opcInfo<opcJle, no_abyte, w_byte, no_reg, noReg, arg_pos, arg_none, no_sr>			; 7E
	opcInfo<opcJg, no_abyte, w_byte, no_reg, noReg, arg_pos, arg_none, no_sr>			; 7F
	;ADD/SUB/CMP
	opcInfo<opcx80, abyte, w_byte, reg_aby, noReg, arg_rm, arg_imm, no_sr>				; 80
	opcInfo<opcx80, abyte, w_word, reg_aby, noReg, arg_rm, arg_imm, no_sr>				; 81
	opcInfo<opcx80, abyte, w_byte, reg_aby, noReg, arg_rm, arg_imm, no_sr>				; 82
	opcInfo<opcx80, abyte, w_word, reg_aby, noReg, arg_rm, arg_imm8_16, no_sr>			; 83
	;TEST
	opcInfo<opcTest, abyte, w_byte, reg_aby, noReg, arg_reg, arg_rm, no_sr>				; 84
	opcInfo<opcTest, abyte, w_word, reg_aby, noReg, arg_reg, arg_rm, no_sr>				; 85
	;XCHG
	opcInfo<opcXchg, abyte, w_byte, reg_aby, noReg, arg_reg, arg_rm, no_sr>				; 86
	opcInfo<opcXchg, abyte, w_word, reg_aby, noReg, arg_reg, arg_rm, no_sr>				; 87
	;MOV
	opcInfo<opcMov, abyte, w_byte, reg_aby, noReg, arg_rm, arg_reg, no_sr>				; 88
	opcInfo<opcMov, abyte, w_word, reg_aby, noReg, arg_rm, arg_reg, no_sr>				; 89
	opcInfo<opcMov, abyte, w_byte, reg_aby, noReg, arg_reg, arg_rm, no_sr>				; 8A
	opcInfo<opcMov, abyte, w_word, reg_aby, noReg, arg_reg, arg_rm, no_sr>				; 8B
	opcInfo<opcMov, abyte, w_word, reg_aby, noReg, arg_rm, arg_reg, sr>					; 8C
	;LEA
	opcInfo<opcLea, abyte, w_word, reg_aby, noReg, arg_reg, arg_rm, no_sr>				; 8D
	;MOV
	opcInfo<opcMov, abyte, w_word, reg_aby, noReg, arg_reg, arg_rm, sr>					; 8E
	;POP
	opcInfo<opcPop, abyte, w_word, no_reg, noReg, arg_rm, arg_none, no_sr>				; 8F
	;XCHGAX
	opcInfo<opcXchgAX, no_abyte, w_word, reg, regAX, arg_reg, arg_none, no_sr>			; 90
	opcInfo<opcXchgAX, no_abyte, w_word, reg, regCX, arg_reg, arg_none, no_sr>			; 91
	opcInfo<opcXchgAX, no_abyte, w_word, reg, regDX, arg_reg, arg_none, no_sr>			; 92
	opcInfo<opcXchgAX, no_abyte, w_word, reg, regBX, arg_reg, arg_none, no_sr>			; 93
	opcInfo<opcXchgAX, no_abyte, w_word, reg, regSP, arg_reg, arg_none, no_sr>			; 94
	opcInfo<opcXchgAX, no_abyte, w_word, reg, regBP, arg_reg, arg_none, no_sr>			; 95
	opcInfo<opcXchgAX, no_abyte, w_word, reg, regSI, arg_reg, arg_none, no_sr>			; 96
	opcInfo<opcXchgAX, no_abyte, w_word, reg, regDI, arg_reg, arg_none, no_sr>			; 97
	;CBW
	opcInfo<opcCbw, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>			; 98
	;CWD
	opcInfo<opcCwd, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>			; 99
	;CALL
	opcInfo<opcCall, no_abyte, w_word, no_reg, noReg, arg_ab, arg_srb, no_sr>			; 9A
	;WAIT
	opcInfo<opcWait, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>		; 9B
	;PUSHF
	opcInfo<opcPushf, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>		; 9C
	;POPF
	opcInfo<opcPopf, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>		; 9D
	;SAHF
	opcInfo<opcSahf, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>		; 9E
	;LAHF
	opcInfo<opcLahf, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>		; 9F
	;MOV Acumalator
	opcInfo<opcMov, no_abyte, w_byte, reg, regAL, arg_reg, arg_ab, no_sr>				; A0
	opcInfo<opcMov, no_abyte, w_word, reg, regAX, arg_reg, arg_ab, no_sr>				; A1
	opcInfo<opcMov, no_abyte, w_byte, reg, regAL, arg_ab, arg_reg, no_sr>				; A2
	opcInfo<opcMov, no_abyte, w_word, reg, regAX, arg_ab, arg_reg, no_sr>				; A3
	;MOVSB; MOVSW
	opcInfo<opcMovsw, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>		; A4
	opcInfo<opcMovsb, no_abyte, w_word, no_reg, noReg, arg_none, arg_none, no_sr>		; A5
	;CMPSB; CMPSW
	opcInfo<opcCmpsb, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>		; A6
	opcInfo<opcCmpsw, no_abyte, w_word, no_reg, noReg, arg_none, arg_none, no_sr>		; A7
	;TEST akumuliatorius ? betarpiškas operandas
	opcInfo<opcTest, no_abyte, w_byte, reg, regAL, arg_reg, arg_imm, no_sr>				; A8
	opcInfo<opcTest, no_abyte, w_word, reg, regAX, arg_reg, arg_imm, no_sr>				; A9
	;STOSB; STOSW
	opcInfo<opcStosb, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>		; AA
	opcInfo<opcStosw, no_abyte, w_word, no_reg, noReg, arg_none, arg_none, no_sr>		; AB
	;LODSB; LODSW
	opcInfo<opcLodsb, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>		; AC
	opcInfo<opcLodsw, no_abyte, w_word, no_reg, noReg, arg_none, arg_none, no_sr>		; AD
	;SCASB; SCASW
	opcInfo<opcScasb, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>		; AE
	opcInfo<opcScasw, no_abyte, w_word, no_reg, noReg, arg_none, arg_none, no_sr>		; AF
	;MOV BYTE
	opcInfo<opcMov, no_abyte, w_byte, reg, regAL, arg_reg, arg_imm, no_sr>				; B0
	opcInfo<opcMov, no_abyte, w_byte, reg, regCL, arg_reg, arg_imm, no_sr>				; B1
	opcInfo<opcMov, no_abyte, w_byte, reg, regDL, arg_reg, arg_imm, no_sr>				; B2
	opcInfo<opcMov, no_abyte, w_byte, reg, regBL, arg_reg, arg_imm, no_sr>				; B3
	opcInfo<opcMov, no_abyte, w_byte, reg, regAH, arg_reg, arg_imm, no_sr>				; B4
	opcInfo<opcMov, no_abyte, w_byte, reg, regCH, arg_reg, arg_imm, no_sr>				; B5
	opcInfo<opcMov, no_abyte, w_byte, reg, regDH, arg_reg, arg_imm, no_sr>				; B6
	opcInfo<opcMov, no_abyte, w_byte, reg, regBH, arg_reg, arg_imm, no_sr>				; B7
	;MOV WORD
	opcInfo<opcMov, no_abyte, w_word, reg, regAX, arg_reg, arg_imm, no_sr>				; B8
	opcInfo<opcMov, no_abyte, w_word, reg, regCX, arg_reg, arg_imm, no_sr>				; B9
	opcInfo<opcMov, no_abyte, w_word, reg, regDX, arg_reg, arg_imm, no_sr>				; BA
	opcInfo<opcMov, no_abyte, w_word, reg, regBX, arg_reg, arg_imm, no_sr>				; BB
	opcInfo<opcMov, no_abyte, w_word, reg, regSP, arg_reg, arg_imm, no_sr>				; BC
	opcInfo<opcMov, no_abyte, w_word, reg, regBP, arg_reg, arg_imm, no_sr>				; BD
	opcInfo<opcMov, no_abyte, w_word, reg, regSI, arg_reg, arg_imm, no_sr>				; BE
	opcInfo<opcMov, no_abyte, w_word, reg, regDI, arg_reg, arg_imm, no_sr>				; BF
	;UNK
	opcInfo<opcUnk, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>			; C0
	opcInfo<opcUnk, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>			; C1
	;RETN
	opcInfo<opcRetn, no_abyte, w_word, no_reg, noReg, arg_imm, arg_none, no_sr>			; C2
	opcInfo<opcRetn, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>		; C3
	;LES
	opcInfo<opcLes, abyte, w_word, reg_aby, noReg, arg_reg, arg_rm, no_sr>				; C4
	;LDS
	opcInfo<opcLds, abyte, w_word, reg_aby, noReg, arg_reg, arg_rm, no_sr>				; C5
	;MOV
	opcInfo<opcMov, abyte, w_byte, no_reg, noReg, arg_rm, arg_imm, no_sr>				; C6
	opcInfo<opcMov, abyte, w_word, no_reg, noReg, arg_rm, arg_imm, no_sr>				; C7
	;UNK
	opcInfo<opcUnk, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>			; C8
	opcInfo<opcUnk, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>			; C9
	;RETF
	opcInfo<opcRetf, no_abyte, w_word, no_reg, noReg, arg_imm, arg_none, no_sr>			; CA
	opcInfo<opcRetf, no_abyte, w_word, no_reg, noReg, arg_none, arg_none, no_sr>		; CB
	;UNK
	opcInfo<opcInt3, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>		; CC
	;INT
	opcInfo<opcInt, no_abyte, w_byte, no_reg, noReg, arg_imm, arg_none, no_sr>			; CD
	;INTO
	opcInfo<opcInto, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>		; CE
	;IRET
	opcInfo<opcIRet, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>		; CF
	;ROL
	opcInfo<opcxD0, abyte, w_byte, no_reg, noReg, arg_rm, arg_one, no_sr>				; D0
	opcInfo<opcxD0, abyte, w_word, no_reg, noReg, arg_rm, arg_one, no_sr>				; D1
	opcInfo<opcxD0, abyte, w_byte, reg, regCL, arg_rm, arg_reg, no_sr>					; D2
	opcInfo<opcxD0, abyte, w_word, reg, regCL, arg_rm, arg_reg, no_sr>					; D3
	;UNK
	opcInfo<opcUnk, abyte, w_byte, no_reg, noReg, arg_rm, arg_none, no_sr>				; D4
	opcInfo<opcUnk, abyte, w_byte, no_reg, noReg, arg_rm, arg_none, no_sr>				; D5
	opcInfo<opcUnk, abyte, w_byte, no_reg, noReg, arg_rm, arg_none, no_sr>				; D6
	;XLAT
	opcInfo<opcXlat, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>		; D7
	;UNK
	opcInfo<opcUnk, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>			; D8
	opcInfo<opcUnk, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>			; D9
	opcInfo<opcUnk, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>			; DA
	opcInfo<opcUnk, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>			; DB
	opcInfo<opcUnk, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>			; DC
	opcInfo<opcUnk, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>			; DD
	opcInfo<opcUnk, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>			; DE
	opcInfo<opcUnk, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>			; DF
	;LOOPNE
	opcInfo<opcLoopne, no_abyte, w_byte, no_reg, noReg, arg_pos, arg_none, no_sr>		; E0
	;LOOPE
	opcInfo<opcLoope, no_abyte, w_byte, no_reg, noReg, arg_pos, arg_none, no_sr>		; E1
	;LOOP/JCXZ
	opcInfo<opcLoop, no_abyte, w_byte, no_reg, noReg, arg_pos, arg_none, no_sr>			; E2
	opcInfo<opcJcxz, no_abyte, w_byte, no_reg, noReg, arg_pos, arg_none, no_sr>			; E3
	;IN/OUT
	opcInfo<opcUnk, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>			; E4
	opcInfo<opcUnk, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>			; E5
	opcInfo<opcUnk, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>			; E6
	opcInfo<opcUnk, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>			; E7
	;CALL/JMP
	opcInfo<opcCall, no_abyte, w_word, no_reg, noReg, arg_pos, arg_none, no_sr>			; E8 Vidinis tiesioginis
	opcInfo<opcJmp, no_abyte, w_word, no_reg, noReg, arg_pos, arg_none, no_sr>			; E9 Vidinis tiesioginis
	opcInfo<opcJmp, no_abyte, w_word, no_reg, noReg, arg_ab, arg_srb, no_sr>			; EA Isorinis tiesioginis
	opcInfo<opcJmp, no_abyte, w_byte, no_reg, noReg, arg_pos, arg_none, no_sr>			; EB Vidinis artimas
	;IN/OUT AL/AX
	opcInfo<opcUnk, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>			; EC
	opcInfo<opcUnk, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>			; ED
	opcInfo<opcUnk, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>			; EE
	opcInfo<opcUnk, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>			; EF
	;LOCK
	opcInfo<opcLock, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>		; F0
	;UNK
	opcInfo<opcUnk, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>			; F1
	;REPNZ
	opcInfo<opcRepnz, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>		; F2
	;REPZ
	opcInfo<opcRepz, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>		; F3
	;HLT
	opcInfo<opcHlt, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>			; F4
	;CMC
	opcInfo<opcCmc, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>			; F5
	;MUL/DIV/TEST/NOT/NEG/IMUL/IDIV
	opcInfo<opcxF6, abyte, w_byte, no_reg, noReg, arg_rm, arg_none, no_sr>				; F6
	;MUL/DIV/TEST/NOT/NEG/IMUL/IDIV
	opcInfo<opcxF6, abyte, w_word, no_reg, noReg, arg_rm, arg_none, no_sr>				; F7
	;CLC
	opcInfo<opcClc, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>			; F8
	;STC
	opcInfo<opcStc, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>			; F9
	;CLI
	opcInfo<opcCli, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>			; FA
	;STI
	opcInfo<opcSti, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>			; FB
	;CLD
	opcInfo<opcCld, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>			; FC
	;STD
	opcInfo<opcStd, no_abyte, w_byte, no_reg, noReg, arg_none, arg_none, no_sr>			; FD
	;INC/DEC
	opcInfo<opcxFE, abyte, w_byte, no_reg, noReg, arg_rm, arg_none, no_sr>				; FE
	;INC/DEC/CALL/CALL/JMP/JMP/PUSH
	opcInfo<opcxFF, abyte, w_word, no_reg, needs_far, arg_rm, arg_none, no_sr>			; FF
