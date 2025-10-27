# Limitations & Tradeoffs

- LLM dependency: Pipeline now requires OpenAI API access; outages, rate limits, or key misconfiguration halt device-type classification.
- IPv6 subnet: We validate IPv6 and produce reverse_ptr, but do not compute `subnet_cidr` for IPv6; derivation requires context we don’t have (prefix policy). 
- Site normalization: The canonicalization (`A–Z`/digits with `-`) may collapse meaningful nuance (e.g., campus/building semantics) without a controlled vocabulary.
- Owner parsing: Email and team extraction are heuristic and can misinterpret free text. Robust mapping usually needs a directory or HR system.
- Device-type confidence: Heuristic classifications set lower confidence and may be biased by naming conventions or notes.
- Operational cost: Each run triggers live LLM calls for ambiguous rows, incurring latency and usage charges.
- Reverse/MX authority: We do not verify DNS authority or name service alignment; `reverse_ptr` is derived mathematically, not validated against DNS.
