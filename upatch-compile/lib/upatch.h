/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2023 Longjun Luo. */
#ifndef __UPATCH_LIB_H_
#define __UPATCH_LIB_H_

int upatch_hijacker_init(void);
int upatch_hijacker_register(const char *prey_name, const char *hijacker_name);
int upatch_hijacker_unregister(const char *prey_name, const char *hijacker_name);
void upatch_hijacker_cleanup(void);

#endif /* __UPATCH_LIB_H_ */
