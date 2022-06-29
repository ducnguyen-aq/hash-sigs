#ifndef PARAM_H
#define PARAM_H

#include "common_defs.h"

#define NIST_LEVEL 6

#ifndef NIST_LEVEL
#define NIST_LEVEL 1
#endif

#define LMS_PUBLICKEYBYTES 60
#define LMS_SECRETKEYBYTES 64

/*
 * I couldn't find security analysis to match NIST security levels anywhere
 * below are security assumptions, need to be revised in the future.
 */
#if NIST_LEVEL == 0
/*
// NIST LEVEL 0: h = 10
+--------------+------------+---------+-------------+-------------+-----------+-------------+
| ParmSet      | KeyGenSize | SigSize | #Signatures | Keypair (s) | Sign (us) | Verify (us) |
+--------------+------------+---------+-------------+-------------+-----------+-------------+
| 10, w=8      | (60, 64)   | 1456    | 2^15 - 1    | 0.41        | 380,520    | 204         | *
*/
#define PARAM_LEVEL 1
#define PARAM_LM_HEIGHT LMS_SHA256_N32_H10
#define PARAM_OTS_WIDTH LMOTS_SHA256_N32_W8

#define LMS_H10_BYTES 1456

#define LMS_SIGNBYTES LMS_H10_BYTES

#elif NIST_LEVEL == 1
/*
// NIST LEVEL 1: h = 15
+--------------+------------+---------+-------------+-------------+-----------+-------------+
| ParmSet      | KeyGenSize | SigSize | #Signatures | Keypair (s) | Sign (us) | Verify (us) |
+--------------+------------+---------+-------------+-------------+-----------+-------------+
| 15, w=8      | (60, 64)   | 1616    | 2^15 - 1    | 12.33       | 12,224,807| 155         | *
*/
#define PARAM_LEVEL 1
#define PARAM_LM_HEIGHT LMS_SHA256_N32_H15
#define PARAM_OTS_WIDTH LMOTS_SHA256_N32_W8

#define LMS_H15_BYTES 1616

#define LMS_SIGNBYTES LMS_H15_BYTES

#elif NIST_LEVEL == 2
/*
+--------------+------------+---------+-------------+-------------+-----------+-------------+
| ParmSet      | KeyGenSize | SigSize | #Signatures | Keypair (s) | Sign (us) | Verify (us) |
+--------------+------------+---------+-------------+-------------+-----------+-------------+
| 5/15 , w=8   | (60, 64)   | 2964    | 2^20 - 1    | 0.01        | 12,317,082| 411         |
| 10/10, w=8   | (60, 64)   | 2964    | 2^20 - 1    | 0.41        | 796,834   | 361         | *
| 15/5 , w=8   | (60, 64)   | 2964    | 2^20 - 1    | 12.21       | 14,186,135| 397         |
*/
#define PARAM_LEVEL 2
#define PARAM_LM_HEIGHT0 LMS_SHA256_N32_H5
#define PARAM_LM_HEIGHT1 LMS_SHA256_N32_H15

#define PARAM_OTS_WIDTH LMOTS_SHA256_N32_W8

// NIST LEVEL 2: h = 20
#define LMS_H20_BYTES 2964

#define LMS_SIGNBYTES LMS_H20_BYTES

#elif NIST_LEVEL == 3
/*
// NIST LEVEL 3: h = 25
+--------------+------------+---------+-------------+-------------+-----------+-------------+
| ParmSet      | KeyGenSize | SigSize | #Signatures | Keypair (s) | Sign (us) | Verify (us) |
+--------------+------------+---------+-------------+-------------+-----------+-------------+
| 10/15, w=8   | (60, 64)   | 3124    | 2^25 - 1    | 0.40        | 12,622,517| 412         | *
| 15/10, w=8   | (60, 64)   | 3124    | 2^25 - 1    | 12.18       | 14,588,549| 389         |
*/
#define PARAM_LEVEL 2
#define PARAM_LM_HEIGHT0 LMS_SHA256_N32_H10
#define PARAM_LM_HEIGHT1 LMS_SHA256_N32_H15
#define PARAM_OTS_WIDTH LMOTS_SHA256_N32_W8

#define LMS_H25_BYTES 3124

#define LMS_SIGNBYTES LMS_H25_BYTES

#elif NIST_LEVEL == 4
/*
// NIST LEVEL 4: h = 30
+--------------+------------+---------+-------------+-------------+-----------+-------------+
| ParmSet      | KeyGenSize | SigSize | #Signatures | Keypair (s) | Sign (us) | Verify (us) |
+--------------+------------+---------+-------------+-------------+-----------+-------------+
| 15/15, w=8   | (60, 64)   | 3284    | 2^30 -1     | 12.19       | 24,639,074| 398         | *
*/
#define PARAM_LEVEL 2
#define PARAM_LM_HEIGHT0 LMS_SHA256_N32_H10
#define PARAM_LM_HEIGHT1 LMS_SHA256_N32_H20

#define PARAM_OTS_WIDTH LMOTS_SHA256_N32_W8

#define LMS_H30_BYTES 3284

#define LMS_SIGNBYTES LMS_H30_BYTES

#elif NIST_LEVEL == 5
/*
// NIST LEVEL 5: h = 35
+--------------+------------+---------+-------------+-------------+-----------+-------------+
| ParmSet      | KeyGenSize | SigSize | #Signatures | Keypair (s) | Sign (us) | Verify (us) |
+--------------+------------+---------+-------------+-------------+-----------+-------------+
| 10/10/15,w=8 | (60, 64)   | 4632    | 2^35 -1     | 0.39        | 13,096,246| 594         | *
*/
#define PARAM_LEVEL 3
#define PARAM_LM_HEIGHT0 LMS_SHA256_N32_H10
#define PARAM_LM_HEIGHT1 LMS_SHA256_N32_H10
#define PARAM_LM_HEIGHT2 LMS_SHA256_N32_H15

#define PARAM_OTS_WIDTH LMOTS_SHA256_N32_W8

#define LMS_H35_BYTES 4632

#define LMS_SIGNBYTES LMS_H35_BYTES

#elif NIST_LEVEL == 6
/*
// NIST LEVEL 6: h = 40
+--------------+------------+---------+-------------+-------------+-----------+-------------+
| ParmSet      | KeyGenSize | SigSize | #Signatures | Keypair (s) | Sign (us) | Verify (us) |
+--------------+------------+---------+-------------+-------------+-----------+-------------+
| 10/15/15, w=8| (60, 64)   | 4792    | 2^40 -1     | 0.41        | 24,956,275| 534         |
*/
#define PARAM_LEVEL 3
#define PARAM_LM_HEIGHT0 LMS_SHA256_N32_H10
#define PARAM_LM_HEIGHT1 LMS_SHA256_N32_H15
#define PARAM_LM_HEIGHT2 LMS_SHA256_N32_H15

#define PARAM_OTS_WIDTH LMOTS_SHA256_N32_W8

#define LMS_H40_BYTES 4792

#define LMS_SIGNBYTES LMS_H40_BYTES

#else
#error "Unspecified NIST_LEVEL {0,1,2,3,4,5,6}"

#endif

#define CRYPTO_PUBLIC_KEY (LMS_PUBLICKEYBYTES)
#define CRYPTO_SECRET_KEY (LMS_SECRETKEYBYTES)
#define CRYPTO_BYTES LMS_SIGNBYTES

#endif
