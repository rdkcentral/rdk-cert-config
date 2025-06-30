/*
 * Copyright 2025 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include<stdio.h>
#include <stdlib.h>
#include "include/l2_tst.h"

int main(int argc, char* argv[])
{
        if(argc < 2)
        {
                ERROR_LOG("Usage : %s <sequence_number>\n", argv[0]);
                return 1;
        }

        int seq= atoi(argv[1]);
        int ret = 0;
        switch( seq )
        {
                case 1:
                        ret = run_seq1cs();
                        break;
                case 2:
                        ret = run_seq2cs();
                        break;
                case 3:
                        ret= run_seq3cs();
                        break;
                case 4:
                        ret= run_seq4cs();
                        break;
		case 5:
			ret= run_seq5cs();
			break;
                case 6:
			ret= run_seq6cs();
			break;
                case 7:
                        ret= run_dualseq1cs();
                        break;
                case 8:
                        ret= run_badseq1();
                        break;
                default:
                        ret = seq;
        }

        if (ret == 0) {
                DEBUG_LOG("Cert selection process %d passed\n", seq);
        }else{
                ERROR_LOG("Cert selection process %d failed\n", seq);
        }
        return ret? 1:0;
}
