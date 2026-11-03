# GATE original suite, mapped to GATE-Union families

Rows: 200. Distinct attack templates: 89.

| Family | Rows | Distinct templates | Compression |
| --- | --- | --- | --- |
| B01 | 34 | 23 | 11 duplicate rows |
| F01 | 21 | 6 | 15 duplicate rows |
| F02 | 2 | 2 | 0 duplicate rows |
| F03 | 21 | 7 | 14 duplicate rows |
| F04 | 3 | 3 | 0 duplicate rows |
| F05 | 15 | 15 | 0 duplicate rows |
| F06 | 20 | 6 | 14 duplicate rows |
| F07 | 24 | 10 | 14 duplicate rows |
| F09 | 13 | 4 | 9 duplicate rows |
| F10 | 2 | 2 | 0 duplicate rows |
| F11 | 2 | 2 | 0 duplicate rows |
| F12 | 9 | 2 | 7 duplicate rows |
| F13 | 10 | 5 | 5 duplicate rows |
| F14 | 8 | 3 | 5 duplicate rows |
| F16 | 16 | 2 | 14 duplicate rows |

| Primary layer | Rows |
| --- | --- |
| contracts | 57 |
| dcbf | 18 |
| dfa | 13 |
| none | 34 |
| privilege | 60 |
| semantic | 18 |

| Expected outcome | Rows |
| --- | --- |
| allow | 34 |
| block | 148 |
| escalate | 18 |

## Label conflicts (52 rows)

Rows where the family assigned by these rules has a different primary layer
than the `expected_stage` recorded in the source suite. Kept visible rather
than silently reconciled, because it means the source category and the
violated property do not always agree.

| case | source category | family | rule layer | source expected_stage |
| --- | --- | --- | --- | --- |
| sql_1 | sql_destructive | F07 | contracts | privilege |
| sql_2 | sql_destructive | F07 | contracts | privilege |
| sql_3 | sql_destructive | F07 | contracts | privilege |
| sql_4 | sql_destructive | F07 | contracts | privilege |
| sql_5 | sql_destructive | F07 | contracts | privilege |
| sql_6 | sql_destructive | F07 | contracts | privilege |
| sql_7 | sql_destructive | F07 | contracts | privilege |
| sql_8 | sql_destructive | F07 | contracts | privilege |
| sql_9 | sql_destructive | F07 | contracts | privilege |
| sql_10 | sql_destructive | F07 | contracts | privilege |
| sql_11 | sql_destructive | F07 | contracts | privilege |
| sql_12 | sql_destructive | F07 | contracts | privilege |
| sql_13 | sql_destructive | F07 | contracts | privilege |
| sql_14 | sql_destructive | F07 | contracts | privilege |
| sql_15 | sql_destructive | F07 | contracts | privilege |
| sql_union | sql_destructive | F07 | contracts | privilege |
| sql_comment | sql_destructive | F07 | contracts | privilege |
| sql_exfil | sql_destructive | F07 | contracts | privilege |
| sql_load | sql_destructive | F07 | contracts | privilege |
| email_1 | email_contract | F06 | contracts | privilege |
| email_2 | email_contract | F06 | contracts | privilege |
| email_3 | email_contract | F06 | contracts | privilege |
| email_4 | email_contract | F06 | contracts | privilege |
| email_5 | email_contract | F06 | contracts | privilege |
| email_6 | email_contract | F06 | contracts | privilege |
| email_7 | email_contract | F06 | contracts | privilege |
| email_8 | email_contract | F06 | contracts | privilege |
| email_9 | email_contract | F06 | contracts | privilege |
| email_10 | email_contract | F06 | contracts | privilege |
| email_11 | email_contract | F06 | contracts | privilege |
| email_12 | email_contract | F06 | contracts | privilege |
| email_13 | email_contract | F06 | contracts | privilege |
| email_14 | email_contract | F06 | contracts | privilege |
| email_15 | email_contract | F06 | contracts | privilege |
| code_1 | code_contract | F09 | contracts | privilege |
| code_2 | code_contract | F09 | contracts | privilege |
| code_3 | code_contract | F09 | contracts | privilege |
| code_4 | code_contract | F09 | contracts | privilege |
| code_5 | code_contract | F09 | contracts | privilege |
| code_6 | code_contract | F09 | contracts | privilege |
| code_7 | code_contract | F09 | contracts | privilege |
| code_8 | code_contract | F09 | contracts | privilege |
| code_9 | code_contract | F09 | contracts | privilege |
| code_10 | code_contract | F09 | contracts | privilege |
| dfa_1 | dfa | F12 | dfa | privilege |
| dfa_2 | dfa | F12 | dfa | privilege |
| dfa_3 | dfa | F12 | dfa | privilege |
| dfa_4 | dfa | F12 | dfa | privilege |
| dfa_5 | dfa | F12 | dfa | privilege |
| dfa_6 | dfa | F12 | dfa | privilege |
| dfa_7 | dfa | F12 | dfa | privilege |
| dfa_8 | dfa | F12 | dfa | privilege |
