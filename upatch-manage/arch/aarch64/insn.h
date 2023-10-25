// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2013 Huawei Ltd.
 * Author: Jiang Liu <liuj97@gmail.com>
 *
 * Copyright (C) 2014-2016 Zi Shen Lim <zlim.lnx@gmail.com>
 */

#ifndef _ARCH_AARCH64_INSN_H
#define _ARCH_AARCH64_INSN_H

#include <endian.h>
#include <linux/types.h>

#include "upatch-relocation.h"

enum aarch64_insn_imm_type {
	AARCH64_INSN_IMM_ADR,
	AARCH64_INSN_IMM_26,
	AARCH64_INSN_IMM_19,
	AARCH64_INSN_IMM_16,
	AARCH64_INSN_IMM_14,
	AARCH64_INSN_IMM_12,
	AARCH64_INSN_IMM_9,
	AARCH64_INSN_IMM_7,
	AARCH64_INSN_IMM_6,
	AARCH64_INSN_IMM_S,
	AARCH64_INSN_IMM_R,
	AARCH64_INSN_IMM_N,
	AARCH64_INSN_IMM_MAX
};

#define SZ_2M 0x00200000
#define ADR_IMM_HILOSPLIT 2
#define ADR_IMM_SIZE SZ_2M
#define ADR_IMM_LOMASK ((1 << ADR_IMM_HILOSPLIT) - 1)
#define ADR_IMM_HIMASK ((ADR_IMM_SIZE >> ADR_IMM_HILOSPLIT) - 1)
#define ADR_IMM_LOSHIFT 29
#define ADR_IMM_HISHIFT 5

#define FAULT_BRK_IMM 0x100

/*
 * BRK instruction encoding
 * The #imm16 value should be placed at bits[20:5] within BRK ins
 */
#define AARCH64_BREAK_MON 0xd4200000

/*
 * BRK instruction for provoking a fault on purpose
 * Unlike kgdb, #imm16 value with unallocated handler is used for faulting.
 */
#define AARCH64_BREAK_FAULT (AARCH64_BREAK_MON | (FAULT_BRK_IMM << 5))

#if BYTE_ORDER == LITTLE_ENDIAN
#define le32_to_cpu(val) (val)
#define cpu_to_le32(val) (val)
#endif
#if BYTE_ORDER == BIG_ENDIAN
#define le32_to_cpu(val) bswap_32(val)
#define cpu_to_le32(val) bswap_32(val)
#endif

u32 aarch64_insn_encode_immediate(enum aarch64_insn_imm_type type, u32 insn,
				  u64 imm);

u64 extract_insn_imm(s64, int, int);

u32 insert_insn_imm(enum aarch64_insn_imm_type, void *, u64);

#endif /* _ARCH_AARCH64_INSN_H */
