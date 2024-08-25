/* SPDX-License-Identifier: BSD-3-Clause */

/*
Copyright (c) 2024 Pluraf Embedded AB <code@pluraf.com>

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
may be used to endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS “AS IS”
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS
BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/


#include <string.h>

#include "../ecc-light-certificate/ecc.h"


#define TRUE 1
#define FALSE 0


void get_curve_param(curve_params_t *para)
{
#ifdef EIGHT_BIT_PROCESSOR
    #error "NOT IMPLEMENTED"
#elif defined(SIXTEEN_BIT_PROCESSOR)
    #error "NOT IMPLEMENTED"
#elif defined(THIRTYTWO_BIT_PROCESSOR)
    // init parameters
    memset(para->p, 0, NUMWORDS * NN_DIGIT_LEN);
    para->p[7] = 0xFFFFFFFF;
    para->p[6] = 0x00000001;
    para->p[5] = 0x00000000;
    para->p[4] = 0x00000000;
    para->p[3] = 0x00000000;
    para->p[2] = 0xFFFFFFFF;
    para->p[1] = 0xFFFFFFFF;
    para->p[0] = 0xFFFFFFFF;

    memset(para->omega, 0, NUMWORDS * NN_DIGIT_LEN);
    para->omega[6] = 0xFFFFFFFE;
    para->omega[5] = 0xFFFFFFFF;
    para->omega[4] = 0xFFFFFFFF;
    para->omega[3] = 0xFFFFFFFF;
    para->omega[2] = 0x00000000;
    para->omega[1] = 0x00000000;
    para->omega[0] = 0x00000001;

    // curve that will be used
    // a = -3
    memset(para->E.a, 0, NUMWORDS * NN_DIGIT_LEN);
    para->E.a[7] = 0xFFFFFFFF;
    para->E.a[6] = 0x00000001;
    para->E.a[5] = 0x00000000;
    para->E.a[4] = 0x00000000;
    para->E.a[3] = 0x00000000;
    para->E.a[2] = 0xFFFFFFFF;
    para->E.a[1] = 0xFFFFFFFF;
    para->E.a[0] = 0xFFFFFFFC;

    para->E.a_minus3 = TRUE;
    para->E.a_zero = FALSE;

    // b = 7
    memset(para->E.b, 0, NUMWORDS * NN_DIGIT_LEN);
    para->G.x[7] = 0x5AC635D8;
    para->G.x[6] = 0xAA3A93E7;
    para->G.x[5] = 0xB3EBBD55;
    para->G.x[4] = 0x769886BC;
    para->G.x[3] = 0x651D06B0;
    para->G.x[2] = 0xCC53B0F6;
    para->G.x[1] = 0x3BCE3C3E;
    para->G.x[0] = 0x27D2604B;

    // base point
    memset(para->G.x, 0, NUMWORDS * NN_DIGIT_LEN);
    para->G.x[7] = 0x6B17D1F2;
    para->G.x[6] = 0xE12C4247;
    para->G.x[5] = 0xF8BCE6E5;
    para->G.x[4] = 0x63A440F2;
    para->G.x[3] = 0x77037D81;
    para->G.x[2] = 0x2DEB33A0;
    para->G.x[1] = 0xF4A13945;
    para->G.x[0] = 0xD898C296;

    memset(para->G.y, 0, NUMWORDS * NN_DIGIT_LEN);
    para->G.y[7] = 0x4FE342E2;
    para->G.y[6] = 0xFE1A7F9B;
    para->G.y[5] = 0x8EE7EB4A;
    para->G.y[4] = 0x7C0F9E16;
    para->G.y[3] = 0x2BCE3357;
    para->G.y[2] = 0x6B315ECE;
    para->G.y[1] = 0xCBB64068;
    para->G.y[0] = 0x37BF51F5;

    // prime divide the number of points
    memset(para->r, 0, NUMWORDS * NN_DIGIT_LEN);
    para->r[7] = 0xFFFFFFFF;
    para->r[6] = 0x00000000;
    para->r[5] = 0xFFFFFFFF;
    para->r[4] = 0xFFFFFFFF;
    para->r[3] = 0xBCE6FAAD;
    para->r[2] = 0xA7179E84;
    para->r[1] = 0xF3B9CAC2;
    para->r[0] = 0xFC632551;
#endif /* THIRTYTWO_BIT_PROCESSOR */
}


NN_UINT omega_mul(NN_DIGIT *a, NN_DIGIT *b, NN_DIGIT *omega, NN_UINT digits)
{
    #ifdef EIGHT_BIT_PROCESSOR
        #error "NOT IMPLEMENTED"
    #elif defined(SIXTEEN_BIT_PROCESSOR)
        #error "NOT IMPLEMENTED"
    #elif defined(THIRTYTWO_BIT_PROCESSOR)
        int omega_digits = 7;
    #endif

    NN_Mult(a, b, omega, digits > omega_digits ? digits : omega_digits);
    return digits + omega_digits;
}
