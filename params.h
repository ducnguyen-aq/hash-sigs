#ifndef PARAM_H
#define PARAM_H

#include "common_defs.h"

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
| 10, w=8      | (60, 64)   | 1456    | 2^15 - 1    | 0.41        | 25390     | 6           | *
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
| 15, w=8      | (60, 64)   | 1616    | 2^15 - 1    | 12.33       | 825,039   | 6           | *
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
| 20, w=8      | (60, 64)   | 1776    | 2^20 - 1    | 392.55      |382,836,815| 55          |
| 5/15 , w=8   | (60, 64)   | 2964    | 2^20 - 1    | 0.01        | 826,462   | 11          |
| 10/10, w=8   | (60, 64)   | 2964    | 2^20 - 1    | 0.41        | 54,336    | 10          | *
| 15/5 , w=8   | (60, 64)   | 2964    | 2^20 - 1    | 12.21       | 952,102   | 10          |
*/
#define PARAM_LEVEL 2
#define PARAM_LM_HEIGHT0 LMS_SHA256_N32_H10
#define PARAM_LM_HEIGHT1 LMS_SHA256_N32_H10

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
| 10/15, w=8   | (60, 64)   | 3124    | 2^25 - 1    | 0.40        | 839,230   | 9           | *
| 15/10, w=8   | (60, 64)   | 3124    | 2^25 - 1    | 12.18       | 972,464   | 22          |
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
| 15/15, w=8   | (60, 64)   | 3284    | 2^30 -1     | 12.19       | 8,300,430 | 46          | *
| 10/20, w=8   | (60, 64)   | 3284    | 2^30 -1     |  0.04       |130,831,902| 54          |
| 20/10, w=8   | (60, 64)   | 3284    | 2^30 -1     | 388.28      |140,263,350| 50          |
*/
#define PARAM_LEVEL 2
#define PARAM_LM_HEIGHT0 LMS_SHA256_N32_H15
#define PARAM_LM_HEIGHT1 LMS_SHA256_N32_H15

#define PARAM_OTS_WIDTH LMOTS_SHA256_N32_W8

#define LMS_H30_BYTES 3284

#define LMS_SIGNBYTES LMS_H30_BYTES

#elif NIST_LEVEL == 5
/*
// NIST LEVEL 5: h = 35
+--------------+------------+---------+-------------+-------------+-----------+-------------+
| ParmSet      | KeyGenSize | SigSize | #Signatures | Keypair (s) | Sign (us) | Verify (us) |
+--------------+------------+---------+-------------+-------------+-----------+-------------+
| 15/20, w=8   | (60, 64)   | 3444    | 2^35 -1     | 12.23       |135,548,270| 57          |
| 10/10/15,w=8 | (60, 64)   | 4632    | 2^35 -1     | 0.39        |  1,873,466| 36          | *
|  5/15/15,w=8 | (60, 64)   | 4632    | 2^35 -1     | 0.02        |  3,539,036| 40          |
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
| 20/20, w=8   | (60, 64)   | 3604    | 2^40 -1     | 391.66      |786,813,578| 444         |
| 10/15/15, w=8| (60, 64)   | 4792    | 2^40 -1     | 0.41        | 25,170,581| 29          |
|  5/15/20, w=8| (60, 64)   | 4792    | 2^40 -1     | 0.02        |405,590,893| 676         |
| 15/15/10, w=8| (60, 64)   | 4792    | 2^40 -1     | 12.30       | 28,932,052| 625         |
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
