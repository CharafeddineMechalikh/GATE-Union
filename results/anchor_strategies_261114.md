# Anchor-substitution coping strategies (measured)

Calibrated on 189 benign calls only: global harm floor 0.7044, per-tool floors 9 tools, degenerate-anchor threshold 0.0776 (smallest benign intent distance).
Recomputed intent distance matches the recorded value on 1700 of 2134 rows (median error 3.0e-07). The 434 deviations are SQL cases whose arguments a contract rewrites (LIMIT clause) before the semantic stage; the decisions below take d_harm and d_safe from the recorded run, so they do not depend on that reconstruction.

```
strategy                  arm                       n  BLOCK   ESC  ALLOW  contained
baseline                  control                 225    215    10      0    100.0%
baseline                  paraphrase              225    222     3      0    100.0%
baseline                  casefold                225    215    10      0    100.0%
baseline                  homoglyph               225     60   165      0    100.0%
baseline                  zero_width              225    206    19      0    100.0%
baseline                  word_split              225    133    86      6     97.3%
baseline                  restructure             167    161     5      1     99.4%
baseline                  retrieval_wrap          167    143    24      0    100.0%
baseline                  anchor_self             225     30    33    162     28.0%
baseline                  anchor_neutral          225    180    43      2     99.1%
baseline                  copy::casefold          225     30    33    162     28.0%
baseline                  copy::homoglyph         225    102    89     34     84.9%
baseline                  copy::paraphrase        225     31    36    158     29.8%
baseline                  copy::restructure       225     33    37    155     31.1%
baseline                  copy::retrieval_wrap    225     33    38    154     31.6%
baseline                  copy::word_split        225     44    91     90     60.0%
baseline                  copy::zero_width        225     31    32    162     28.0%
baseline                  benign                  189      0     9    180      4.8%

S1_provenance_verified    control                 225    215    10      0    100.0%
S1_provenance_verified    paraphrase              225    222     3      0    100.0%
S1_provenance_verified    casefold                225    215    10      0    100.0%
S1_provenance_verified    homoglyph               225     60   165      0    100.0%
S1_provenance_verified    zero_width              225    206    19      0    100.0%
S1_provenance_verified    word_split              225    133    86      6     97.3%
S1_provenance_verified    restructure             167    161     5      1     99.4%
S1_provenance_verified    retrieval_wrap          167    143    24      0    100.0%
S1_provenance_verified    anchor_self             225     30    33    162     28.0%
S1_provenance_verified    anchor_neutral          225    180    43      2     99.1%
S1_provenance_verified    copy::casefold          225     30    33    162     28.0%
S1_provenance_verified    copy::homoglyph         225    102    89     34     84.9%
S1_provenance_verified    copy::paraphrase        225     31    36    158     29.8%
S1_provenance_verified    copy::restructure       225     33    37    155     31.1%
S1_provenance_verified    copy::retrieval_wrap    225     33    38    154     31.6%
S1_provenance_verified    copy::word_split        225     44    91     90     60.0%
S1_provenance_verified    copy::zero_width        225     31    32    162     28.0%
S1_provenance_verified    benign                  189      0     9    180      4.8%

S1_provenance_unverified  control                 225    215    10      0    100.0%
S1_provenance_unverified  paraphrase              225    222     3      0    100.0%
S1_provenance_unverified  casefold                225    215    10      0    100.0%
S1_provenance_unverified  homoglyph               225     60   165      0    100.0%
S1_provenance_unverified  zero_width              225    206    19      0    100.0%
S1_provenance_unverified  word_split              225    133    92      0    100.0%
S1_provenance_unverified  restructure             167    161     6      0    100.0%
S1_provenance_unverified  retrieval_wrap          167    144    23      0    100.0%
S1_provenance_unverified  anchor_self             225     99   126      0    100.0%
S1_provenance_unverified  anchor_neutral          225    181    44      0    100.0%
S1_provenance_unverified  copy::casefold          225     99   126      0    100.0%
S1_provenance_unverified  copy::homoglyph         225    126    99      0    100.0%
S1_provenance_unverified  copy::paraphrase        225     99   126      0    100.0%
S1_provenance_unverified  copy::restructure       225     99   126      0    100.0%
S1_provenance_unverified  copy::retrieval_wrap    225     99   126      0    100.0%
S1_provenance_unverified  copy::word_split        225     99   126      0    100.0%
S1_provenance_unverified  copy::zero_width        225     99   126      0    100.0%
S1_provenance_unverified  benign                  189     13   176      0    100.0%

S2_degenerate_detector    control                 225    215    10      0    100.0%
S2_degenerate_detector    paraphrase              225    222     3      0    100.0%
S2_degenerate_detector    casefold                225    215    10      0    100.0%
S2_degenerate_detector    homoglyph               225     60   165      0    100.0%
S2_degenerate_detector    zero_width              225    206    19      0    100.0%
S2_degenerate_detector    word_split              225    133    86      6     97.3%
S2_degenerate_detector    restructure             167    161     5      1     99.4%
S2_degenerate_detector    retrieval_wrap          167    143    24      0    100.0%
S2_degenerate_detector    anchor_self             225     99   126      0    100.0%
S2_degenerate_detector    anchor_neutral          225    180    43      2     99.1%
S2_degenerate_detector    copy::casefold          225     99   126      0    100.0%
S2_degenerate_detector    copy::homoglyph         225    102    89     34     84.9%
S2_degenerate_detector    copy::paraphrase        225     99   123      3     98.7%
S2_degenerate_detector    copy::restructure       225     94   127      4     98.2%
S2_degenerate_detector    copy::retrieval_wrap    225     82   142      1     99.6%
S2_degenerate_detector    copy::word_split        225     47    95     83     63.1%
S2_degenerate_detector    copy::zero_width        225     99   126      0    100.0%
S2_degenerate_detector    benign                  189      0     9    180      4.8%

S3_global_floor           control                 225    215    10      0    100.0%
S3_global_floor           paraphrase              225    222     3      0    100.0%
S3_global_floor           casefold                225    215    10      0    100.0%
S3_global_floor           homoglyph               225     60   165      0    100.0%
S3_global_floor           zero_width              225    206    19      0    100.0%
S3_global_floor           word_split              225    133    86      6     97.3%
S3_global_floor           restructure             167    161     5      1     99.4%
S3_global_floor           retrieval_wrap          167    144    23      0    100.0%
S3_global_floor           anchor_self             225     99     0    126     44.0%
S3_global_floor           anchor_neutral          225    181    42      2     99.1%
S3_global_floor           copy::casefold          225     99     0    126     44.0%
S3_global_floor           copy::homoglyph         225    126    66     33     85.3%
S3_global_floor           copy::paraphrase        225     99     0    126     44.0%
S3_global_floor           copy::restructure       225     99     0    126     44.0%
S3_global_floor           copy::retrieval_wrap    225     99     0    126     44.0%
S3_global_floor           copy::word_split        225     99    43     83     63.1%
S3_global_floor           copy::zero_width        225     99     0    126     44.0%
S3_global_floor           benign                  189     13     9    167     11.6%

S4_margin                 control                 225    224     1      0    100.0%
S4_margin                 paraphrase              225    223     2      0    100.0%
S4_margin                 casefold                225    224     1      0    100.0%
S4_margin                 homoglyph               225    105   120      0    100.0%
S4_margin                 zero_width              225    218     7      0    100.0%
S4_margin                 word_split              225    133    86      6     97.3%
S4_margin                 restructure             167    161     5      1     99.4%
S4_margin                 retrieval_wrap          167    154    13      0    100.0%
S4_margin                 anchor_self             225    195     0     30     86.7%
S4_margin                 anchor_neutral          225    197    26      2     99.1%
S4_margin                 copy::casefold          225    195     0     30     86.7%
S4_margin                 copy::homoglyph         225    195     0     30     86.7%
S4_margin                 copy::paraphrase        225    195     0     30     86.7%
S4_margin                 copy::restructure       225    195     0     30     86.7%
S4_margin                 copy::retrieval_wrap    225    195     0     30     86.7%
S4_margin                 copy::word_split        225    195     0     30     86.7%
S4_margin                 copy::zero_width        225    195     0     30     86.7%
S4_margin                 benign                  189      5     5    179      5.3%

S5_tool_floor             control                 225    224     1      0    100.0%
S5_tool_floor             paraphrase              225    223     2      0    100.0%
S5_tool_floor             casefold                225    224     1      0    100.0%
S5_tool_floor             homoglyph               225     60   165      0    100.0%
S5_tool_floor             zero_width              225    217     8      0    100.0%
S5_tool_floor             word_split              225    161    58      6     97.3%
S5_tool_floor             restructure             167    161     5      1     99.4%
S5_tool_floor             retrieval_wrap          167    144    23      0    100.0%
S5_tool_floor             anchor_self             225    157     0     68     69.8%
S5_tool_floor             anchor_neutral          225    181    42      2     99.1%
S5_tool_floor             copy::casefold          225    157     0     68     69.8%
S5_tool_floor             copy::homoglyph         225    159    33     33     85.3%
S5_tool_floor             copy::paraphrase        225    157     0     68     69.8%
S5_tool_floor             copy::restructure       225    157     0     68     69.8%
S5_tool_floor             copy::retrieval_wrap    225    157     0     68     69.8%
S5_tool_floor             copy::word_split        225    157    10     58     74.2%
S5_tool_floor             copy::zero_width        225    157     0     68     69.8%
S5_tool_floor             benign                  189     63     8    118     37.6%

S2_plus_S4                control                 225    215    10      0    100.0%
S2_plus_S4                paraphrase              225    222     3      0    100.0%
S2_plus_S4                casefold                225    215    10      0    100.0%
S2_plus_S4                homoglyph               225     60   165      0    100.0%
S2_plus_S4                zero_width              225    206    19      0    100.0%
S2_plus_S4                word_split              225    133    86      6     97.3%
S2_plus_S4                restructure             167    161     5      1     99.4%
S2_plus_S4                retrieval_wrap          167    143    24      0    100.0%
S2_plus_S4                anchor_self             225    195     0     30     86.7%
S2_plus_S4                anchor_neutral          225    180    43      2     99.1%
S2_plus_S4                copy::casefold          225    195     0     30     86.7%
S2_plus_S4                copy::homoglyph         225    102    89     34     84.9%
S2_plus_S4                copy::paraphrase        225    193     0     32     85.8%
S2_plus_S4                copy::restructure       225    188     4     33     85.3%
S2_plus_S4                copy::retrieval_wrap    225    178    17     30     86.7%
S2_plus_S4                copy::word_split        225     52    89     84     62.7%
S2_plus_S4                copy::zero_width        225    195     0     30     86.7%
S2_plus_S4                benign                  189      0     9    180      4.8%

S1_plus_S3                control                 225    215    10      0    100.0%
S1_plus_S3                paraphrase              225    222     3      0    100.0%
S1_plus_S3                casefold                225    215    10      0    100.0%
S1_plus_S3                homoglyph               225     60   165      0    100.0%
S1_plus_S3                zero_width              225    206    19      0    100.0%
S1_plus_S3                word_split              225    133    86      6     97.3%
S1_plus_S3                restructure             167    161     5      1     99.4%
S1_plus_S3                retrieval_wrap          167    144    23      0    100.0%
S1_plus_S3                anchor_self             225     99     0    126     44.0%
S1_plus_S3                anchor_neutral          225    181    42      2     99.1%
S1_plus_S3                copy::casefold          225     99     0    126     44.0%
S1_plus_S3                copy::homoglyph         225    126    66     33     85.3%
S1_plus_S3                copy::paraphrase        225     99     0    126     44.0%
S1_plus_S3                copy::restructure       225     99     0    126     44.0%
S1_plus_S3                copy::retrieval_wrap    225     99     0    126     44.0%
S1_plus_S3                copy::word_split        225     99    43     83     63.1%
S1_plus_S3                copy::zero_width        225     99     0    126     44.0%
S1_plus_S3                benign                  189     13     9    167     11.6%

```

Leave-one-out false blocks on the benign corpus: global floor 13/189, per-tool floor 63/189.
