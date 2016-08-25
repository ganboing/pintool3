/*BEGIN_LEGAL 
Intel Open Source License 

Copyright (c) 2002-2016 Intel Corporation. All rights reserved.
 
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.  Redistributions
in binary form must reproduce the above copyright notice, this list of
conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.  Neither the name of
the Intel Corporation nor the names of its contributors may be used to
endorse or promote products derived from this software without
specific prior written permission.
 
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE INTEL OR
ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
END_LEGAL */
/// @file xed-operand-enum.h

// This file was automatically generated.
// Do not edit this file.

#if !defined(_XED_OPERAND_ENUM_H_)
# define _XED_OPERAND_ENUM_H_
#include "xed-common-hdrs.h"
typedef enum {
  XED_OPERAND_INVALID,
  XED_OPERAND_AGEN,
  XED_OPERAND_AMD3DNOW,
  XED_OPERAND_ASZ,
  XED_OPERAND_BASE0,
  XED_OPERAND_BASE1,
  XED_OPERAND_BCAST,
  XED_OPERAND_BCRC,
  XED_OPERAND_BRDISP_WIDTH,
  XED_OPERAND_CHIP,
  XED_OPERAND_DEFAULT_SEG,
  XED_OPERAND_DF32,
  XED_OPERAND_DF64,
  XED_OPERAND_DISP_WIDTH,
  XED_OPERAND_DISP,
  XED_OPERAND_DUMMY,
  XED_OPERAND_EASZ,
  XED_OPERAND_ELEMENT_SIZE,
  XED_OPERAND_ENCODER_PREFERRED,
  XED_OPERAND_EOSZ,
  XED_OPERAND_ERROR,
  XED_OPERAND_ESRC,
  XED_OPERAND_ESRC3,
  XED_OPERAND_EVEXRR,
  XED_OPERAND_FIRST_F2F3,
  XED_OPERAND_HAS_SIB,
  XED_OPERAND_HAS_MODRM,
  XED_OPERAND_HINT,
  XED_OPERAND_HSW,
  XED_OPERAND_ICLASS,
  XED_OPERAND_ILD_F2,
  XED_OPERAND_ILD_F3,
  XED_OPERAND_ILD_SEG,
  XED_OPERAND_IMM_WIDTH,
  XED_OPERAND_IMM0SIGNED,
  XED_OPERAND_IMM0,
  XED_OPERAND_IMM1_BYTES,
  XED_OPERAND_IMM1,
  XED_OPERAND_INDEX,
  XED_OPERAND_LAST_F2F3,
  XED_OPERAND_LLRC,
  XED_OPERAND_LOCK,
  XED_OPERAND_MAP,
  XED_OPERAND_MASK,
  XED_OPERAND_MAX_BYTES,
  XED_OPERAND_MEM_WIDTH,
  XED_OPERAND_MEM0,
  XED_OPERAND_MEM1,
  XED_OPERAND_MOD,
  XED_OPERAND_MODE_FIRST_PREFIX,
  XED_OPERAND_MODE,
  XED_OPERAND_MODEP5,
  XED_OPERAND_MODEP55C,
  XED_OPERAND_MODRM,
  XED_OPERAND_MODRM_BYTE,
  XED_OPERAND_MPXMODE,
  XED_OPERAND_NEED_MEMDISP,
  XED_OPERAND_NEEDREX,
  XED_OPERAND_NELEM,
  XED_OPERAND_NO_SCALE_DISP8,
  XED_OPERAND_NOMINAL_OPCODE,
  XED_OPERAND_NOREX,
  XED_OPERAND_NPREFIXES,
  XED_OPERAND_NREXES,
  XED_OPERAND_NSEG_PREFIXES,
  XED_OPERAND_OSZ,
  XED_OPERAND_OUT_OF_BYTES,
  XED_OPERAND_OUTREG,
  XED_OPERAND_P4,
  XED_OPERAND_POS_SIB,
  XED_OPERAND_POS_DISP,
  XED_OPERAND_POS_IMM,
  XED_OPERAND_POS_NOMINAL_OPCODE,
  XED_OPERAND_POS_IMM1,
  XED_OPERAND_POS_MODRM,
  XED_OPERAND_PREFIX66,
  XED_OPERAND_PTR,
  XED_OPERAND_REALMODE,
  XED_OPERAND_REG,
  XED_OPERAND_REG0,
  XED_OPERAND_REG1,
  XED_OPERAND_REG2,
  XED_OPERAND_REG3,
  XED_OPERAND_REG4,
  XED_OPERAND_REG5,
  XED_OPERAND_REG6,
  XED_OPERAND_REG7,
  XED_OPERAND_REG8,
  XED_OPERAND_RELBR,
  XED_OPERAND_REP,
  XED_OPERAND_REX,
  XED_OPERAND_REXB,
  XED_OPERAND_REXR,
  XED_OPERAND_REXRR,
  XED_OPERAND_REXW,
  XED_OPERAND_REXX,
  XED_OPERAND_RM,
  XED_OPERAND_ROUNDC,
  XED_OPERAND_SAE,
  XED_OPERAND_SCALE,
  XED_OPERAND_SEG_OVD,
  XED_OPERAND_SEG0,
  XED_OPERAND_SEG1,
  XED_OPERAND_SIB,
  XED_OPERAND_SIBBASE,
  XED_OPERAND_SIBINDEX,
  XED_OPERAND_SIBSCALE,
  XED_OPERAND_SKIP_OSZ,
  XED_OPERAND_SMODE,
  XED_OPERAND_SRM,
  XED_OPERAND_TYPE,
  XED_OPERAND_UBIT,
  XED_OPERAND_UIMM0,
  XED_OPERAND_UIMM1,
  XED_OPERAND_USING_DEFAULT_SEGMENT0,
  XED_OPERAND_USING_DEFAULT_SEGMENT1,
  XED_OPERAND_VEX_C4,
  XED_OPERAND_VEX_PREFIX,
  XED_OPERAND_VEXDEST3,
  XED_OPERAND_VEXDEST4,
  XED_OPERAND_VEXDEST210,
  XED_OPERAND_VEXVALID,
  XED_OPERAND_VL,
  XED_OPERAND_ZEROING,
  XED_OPERAND_LAST
} xed_operand_enum_t;

/// This converts strings to #xed_operand_enum_t types.
/// @param s A C-string.
/// @return #xed_operand_enum_t
/// @ingroup ENUM
XED_DLL_EXPORT xed_operand_enum_t str2xed_operand_enum_t(const char* s);
/// This converts strings to #xed_operand_enum_t types.
/// @param p An enumeration element of type xed_operand_enum_t.
/// @return string
/// @ingroup ENUM
XED_DLL_EXPORT const char* xed_operand_enum_t2str(const xed_operand_enum_t p);

/// Returns the last element of the enumeration
/// @return xed_operand_enum_t The last element of the enumeration.
/// @ingroup ENUM
XED_DLL_EXPORT xed_operand_enum_t xed_operand_enum_t_last(void);
#endif
