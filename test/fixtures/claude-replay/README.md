# Synthetic Claude hook regression fixtures

These fixed, synthetic payloads cover session Git identity retention, tool
outcomes, capture evidence, and metadata-only privacy behavior. They are test
inputs, not real captured sessions or proof of live hook delivery.

Only the session-start payload includes a working directory. Tests rely on later
payloads omitting it to exercise identity retention. Keep these inputs independent
of documentation demos and the ignored `.demo/` recording environment.
