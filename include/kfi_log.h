/*
 * Copyright (c) 2015 NetApp, Inc.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL); Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef _KFI_LOG_H_
#define _KFI_LOG_H_

#include <linux/printk.h>

#ifndef MODULE_NAME
#define MODULE_NAME "KFI"
#endif

#define LOG_DEBUG(fmt, ...) pr_debug("%s - %s:%d " fmt "\n", \
	MODULE_NAME, __func__, __LINE__, ##__VA_ARGS__)

#define LOG_DEFAULT(fmt, ...) pr_default("%s: " fmt "\n", \
	MODULE_NAME, ##__VA_ARGS__)

#define LOG_INFO(fmt, ...) pr_info("%s: " fmt "\n", \
	MODULE_NAME, ##__VA_ARGS__)

#define LOG_NOTICE(fmt, ...) pr_notice("%s: " fmt "\n", \
	MODULE_NAME, ##__VA_ARGS__)

#define LOG_WARN(fmt, ...) pr_warn("%s - %s:%d: " fmt "\n", \
	MODULE_NAME, __func__, __LINE__, ##__VA_ARGS__)

#define LOG_ERR(fmt, ...) pr_err("%s - %s:%d: " fmt "\n", \
	MODULE_NAME, __func__, __LINE__, ##__VA_ARGS__)

#define LOG_ERR_RL(fmt, ...) pr_err_ratelimited("%s - %s:%d: " fmt "\n", \
	MODULE_NAME, __func__, __LINE__, ##__VA_ARGS__)

#define LOG_CRIT(fmt, ...) pr_crit("%s - %s:%d: " fmt "\n", \
	MODULE_NAME, __func__, __LINE__, ##__VA_ARGS__)

#define LOG_ALERT(fmt, ...) pr_alert("%s - %s:%d: " fmt "\n", \
	MODULE_NAME, __func__, __LINE__, ##__VA_ARGS__)

#define LOG_EMERG(fmt, ...) pr_emerg("%s - %s:%d: " fmt "\n", \
	MODULE_NAME, __func__, __LINE__, ##__VA_ARGS__)

#endif /* _KFI_LOG_H_ */
