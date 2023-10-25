// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 HUAWEI, Inc.
 *
 * Authors:
 *   renoseven <dev@renoseven.net>
 *   Zongwu Li <lzw32321226@gmail.com>
 *
 */

#include <errno.h>

#include "insn.h"
#include "upatch-relocation.h"
#include "upatch-resolve.h"

#define TCB_SIZE 2 * sizeof(void *)

enum aarch64_reloc_op {
	RELOC_OP_NONE,
	RELOC_OP_ABS,
	RELOC_OP_PREL,
	RELOC_OP_PAGE,
};

static inline s64 calc_reloc(enum aarch64_reloc_op op, void *place, u64 val)
{
	s64 sval;
	switch (op) {
	case RELOC_OP_ABS:
		// S + A
		sval = val;
		break;
	case RELOC_OP_PREL:
		// S + A - P
		sval = val - (u64)place;
		break;
	case RELOC_OP_PAGE:
		// Page(S + A) - Page(P)
		sval = (val & ~0xfff) - ((u64)place & ~0xfff);
		break;
	default:
		log_error("upatch: unknown relocation operation %d\n", op);
		break;
	}

	log_debug("upatch: reloc, S+A=0x%lx, P=0x%lx, X=0x%lx\n", val,
		  (u64)place, sval);
	return sval;
}

int apply_relocate_add(struct upatch_elf *uelf, unsigned int symindex,
		       unsigned int relsec)
{
	unsigned int i;
	GElf_Sym *sym;
	char const *sym_name;
	void *loc;
	void *uloc;
	u64 val;
	s64 result;
	GElf_Shdr *shdrs = (void *)uelf->info.shdrs;
	GElf_Rela *rel = (void *)shdrs[relsec].sh_addr;

	for (i = 0; i < shdrs[relsec].sh_size / sizeof(*rel); i++) {
		/* loc corresponds to P in the kernel space */
		loc = (void *)shdrs[shdrs[relsec].sh_info].sh_addr +
		      rel[i].r_offset;

		// /* uloc corresponds P in user space */
		uloc = (void *)shdrs[shdrs[relsec].sh_info].sh_addralign +
		       rel[i].r_offset;

		/* sym is the ELF symbol we're referring to */
		sym = (GElf_Sym *)shdrs[symindex].sh_addr +
		      GELF_R_SYM(rel[i].r_info);
		if (GELF_ST_TYPE(sym[i].st_info) == STT_SECTION &&
		    sym->st_shndx < uelf->info.hdr->e_shnum)
			sym_name = uelf->info.shstrtab +
				   shdrs[sym->st_shndx].sh_name;
		else
			sym_name = uelf->strtab + sym->st_name;

		/* val corresponds to (S + A) */
		val = (s64)(sym->st_value + rel[i].r_addend);
		log_debug(
			"upatch: reloc symbol, name=%s, k_addr=0x%lx, u_addr=0x%lx, "
			"r_offset=0x%lx, st_value=0x%lx, r_addend=0x%lx \n",
			sym_name, shdrs[shdrs[relsec].sh_info].sh_addr,
			shdrs[shdrs[relsec].sh_info].sh_addralign,
			rel[i].r_offset, sym->st_value, rel[i].r_addend);

		/* Perform the static relocation. */
		switch (GELF_R_TYPE(rel[i].r_info)) {
		case R_AARCH64_NONE:
			break;
		/* Data relocations. */
		case R_AARCH64_ABS64:
			result = calc_reloc(RELOC_OP_ABS, uloc, val);
			*(s64 *)loc = result;
			break;
		case R_AARCH64_ABS32:
			result = calc_reloc(RELOC_OP_ABS, uloc, val);
			if (result < -(s64)BIT(31) || result >= (s64)BIT(32))
				goto overflow;
			*(s32 *)loc = result;
			break;
		case R_AARCH64_ABS16:
			result = calc_reloc(RELOC_OP_ABS, uloc, val);
			if (result < -(s64)BIT(15) || result >= (s64)BIT(16))
				goto overflow;
			*(s16 *)loc = result;
			break;
		case R_AARCH64_PREL64:
			result = calc_reloc(RELOC_OP_PREL, uloc, val);
			*(s64 *)loc = result;
			break;
		case R_AARCH64_PREL32:
			result = calc_reloc(RELOC_OP_PREL, uloc, val);
			if (result < -(s64)BIT(31) || result >= (s64)BIT(32))
				goto overflow;
			*(s32 *)loc = result;
			break;
		case R_AARCH64_PREL16:
			result = calc_reloc(RELOC_OP_PREL, uloc, val);
			if (result < -(s64)BIT(15) || result >= (s64)BIT(16))
				goto overflow;
			*(s16 *)loc = result;
			break;
		/* Immediate instruction relocations. */
		case R_AARCH64_LD_PREL_LO19:
			result = calc_reloc(RELOC_OP_PREL, uloc, val);
			if (result < -(s64)BIT(20) || result >= (s64)BIT(20))
				goto overflow;
			result = extract_insn_imm(result, 19, 2);
			result = insert_insn_imm(AARCH64_INSN_IMM_19, loc,
						 result);
			*(__le32 *)loc = cpu_to_le32(result);
			break;
		case R_AARCH64_ADR_PREL_LO21:
			result = calc_reloc(RELOC_OP_PREL, uloc, val);
			if (result < -(s64)BIT(20) || result >= (s64)BIT(20))
				goto overflow;
			result = extract_insn_imm(result, 21, 0);
			result = insert_insn_imm(AARCH64_INSN_IMM_ADR, loc,
						 result);
			*(__le32 *)loc = cpu_to_le32(result);
			break;
		case R_AARCH64_ADR_PREL_PG_HI21:
			result = calc_reloc(RELOC_OP_PAGE, uloc, val);
			if (result < -(s64)BIT(32) || result >= (s64)BIT(32))
				goto overflow;
			result = extract_insn_imm(result, 21, 12);
			result = insert_insn_imm(AARCH64_INSN_IMM_ADR, loc,
						 result);
			*(__le32 *)loc = cpu_to_le32(result);
			break;
		case R_AARCH64_ADR_PREL_PG_HI21_NC:
			result = calc_reloc(RELOC_OP_PAGE, uloc, val);
			result = extract_insn_imm(result, 21, 12);
			result = insert_insn_imm(AARCH64_INSN_IMM_ADR, loc,
						 result);
			*(__le32 *)loc = cpu_to_le32(result);
			break;
		case R_AARCH64_ADD_ABS_LO12_NC:
		case R_AARCH64_LDST8_ABS_LO12_NC:
			result = calc_reloc(RELOC_OP_ABS, uloc, val);
			result = extract_insn_imm(result, 12, 0);
			result = insert_insn_imm(AARCH64_INSN_IMM_12, loc,
						 result);
			*(__le32 *)loc = cpu_to_le32(result);
			break;
		case R_AARCH64_LDST16_ABS_LO12_NC:
			result = calc_reloc(RELOC_OP_ABS, uloc, val);
			result = extract_insn_imm(result, 11, 1);
			result = insert_insn_imm(AARCH64_INSN_IMM_12, loc,
						 result);
			*(__le32 *)loc = cpu_to_le32(result);
			break;
		case R_AARCH64_LDST32_ABS_LO12_NC:
			result = calc_reloc(RELOC_OP_ABS, uloc, val);
			result = extract_insn_imm(result, 10, 2);
			result = insert_insn_imm(AARCH64_INSN_IMM_12, loc,
						 result);
			*(__le32 *)loc = cpu_to_le32(result);
			break;
		case R_AARCH64_LDST64_ABS_LO12_NC:
			result = calc_reloc(RELOC_OP_ABS, uloc, val);
			result = extract_insn_imm(result, 9, 3);
			result = insert_insn_imm(AARCH64_INSN_IMM_12, loc,
						 result);
			*(__le32 *)loc = cpu_to_le32(result);
			break;
		case R_AARCH64_LDST128_ABS_LO12_NC:
			result = calc_reloc(RELOC_OP_ABS, uloc, val);
			result = extract_insn_imm(result, 8, 4);
			result = insert_insn_imm(AARCH64_INSN_IMM_12, loc,
						 result);
			*(__le32 *)loc = cpu_to_le32(result);
			break;
		case R_AARCH64_TSTBR14:
			result = calc_reloc(RELOC_OP_PREL, uloc, val);
			if (result < -(s64)BIT(15) || result >= (s64)BIT(15))
				goto overflow;
			result = extract_insn_imm(result, 14, 2);
			result = insert_insn_imm(AARCH64_INSN_IMM_14, loc,
						 result);
			*(__le32 *)loc = cpu_to_le32(result);
			break;
		case R_AARCH64_CONDBR19:
			result = calc_reloc(RELOC_OP_PREL, uloc, val);
			result = extract_insn_imm(result, 19, 2);
			result = insert_insn_imm(AARCH64_INSN_IMM_19, loc,
						 result);
			*(__le32 *)loc = cpu_to_le32(result);
			break;
		case R_AARCH64_JUMP26:
		case R_AARCH64_CALL26:
			result = calc_reloc(RELOC_OP_PREL, uloc, val);
			if (result < -(s64)BIT(27) || result >= (s64)BIT(27)) {
				log_debug(
					"R_AARCH64_CALL26 overflow: result = 0x%lx, uloc = "
					"0x%lx, val = 0x%lx\n",
					result, (unsigned long)uloc, val);
				val = search_insert_plt_table(uelf, val,
							      (u64)&val);
				log_debug(
					"R_AARCH64_CALL26 overflow: plt.addr = 0x%lx\n",
					val);
				if (!val)
					goto overflow;
				result = calc_reloc(RELOC_OP_PREL, uloc, val);
			}
			result = extract_insn_imm(result, 26, 2);
			result = insert_insn_imm(AARCH64_INSN_IMM_26, loc,
						 result);
			*(__le32 *)loc = cpu_to_le32(result);
			break;
		case R_AARCH64_ADR_GOT_PAGE:
			result = calc_reloc(RELOC_OP_PAGE, uloc, val);
			if (result < -(s64)BIT(32) || result >= (s64)BIT(32))
				goto overflow;
			result = extract_insn_imm(result, 21, 12);
			result = insert_insn_imm(AARCH64_INSN_IMM_ADR, loc,
						 result);
			*(__le32 *)loc = cpu_to_le32(result);
			break;
		case R_AARCH64_LD64_GOT_LO12_NC:
			result = calc_reloc(RELOC_OP_ABS, uloc, val);
			// don't check result & 7 == 0.
			// sometimes, result & 7 != 0, it works fine.
			result = extract_insn_imm(result, 9, 3);
			result = insert_insn_imm(AARCH64_INSN_IMM_12, loc,
						 result);
			*(__le32 *)loc = cpu_to_le32(result);
			break;
		case R_AARCH64_TLSLE_ADD_TPREL_HI12:
			result = ALIGN(TCB_SIZE, uelf->relf->tls_align) + val;
			if (result < 0 || result >= BIT(24))
				goto overflow;
			result = extract_insn_imm(result, 12, 12);
			result = insert_insn_imm(AARCH64_INSN_IMM_12, loc,
						 result);
			*(__le32 *)loc = cpu_to_le32(result);
			break;
		case R_AARCH64_TLSLE_ADD_TPREL_LO12_NC:
			result = ALIGN(TCB_SIZE, uelf->relf->tls_align) + val;
			result = extract_insn_imm(result, 12, 0);
			result = insert_insn_imm(AARCH64_INSN_IMM_12, loc,
						 result);
			*(__le32 *)loc = cpu_to_le32(result);
			break;
		case R_AARCH64_TLSDESC_ADR_PAGE21:
			result = calc_reloc(RELOC_OP_PAGE, uloc, val);
			if (result < -(s64)BIT(32) || result >= (s64)BIT(32))
				goto overflow;
			result = extract_insn_imm(result, 21, 12);
			result = insert_insn_imm(AARCH64_INSN_IMM_ADR, loc,
						 result);
			*(__le32 *)loc = cpu_to_le32(result);
			break;
		case R_AARCH64_TLSDESC_LD64_LO12:
			result = calc_reloc(RELOC_OP_ABS, uloc, val);
			// don't check result & 7 == 0.
			result = extract_insn_imm(result, 9, 3);
			result = insert_insn_imm(AARCH64_INSN_IMM_12, loc,
						 result);
			*(__le32 *)loc = cpu_to_le32(result);
			break;
		case R_AARCH64_TLSDESC_ADD_LO12:
			result = calc_reloc(RELOC_OP_ABS, uloc, val);
			result = extract_insn_imm(result, 12, 0);
			result = insert_insn_imm(AARCH64_INSN_IMM_12, loc,
						 result);
			*(__le32 *)loc = cpu_to_le32(result);
			break;
		case R_AARCH64_TLSDESC_CALL:
			// this is a blr instruction, don't need to modify
			break;

		default:
			log_error("upatch: unsupported RELA relocation: %lu\n",
				  GELF_R_TYPE(rel[i].r_info));
			return -ENOEXEC;
		}
	}
	return 0;

overflow:
	log_error("upatch: overflow in relocation type %d val %lx reloc %lx\n",
		  (int)GELF_R_TYPE(rel[i].r_info), val, result);
	return -ENOEXEC;
}
