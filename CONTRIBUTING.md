# Contributing

This code is free, open-source and public. Every change must read
plainly to a stranger: the code says what it does, the README says what
it promises, and `docs/contracts.md` says who owns unfinished work at
every handoff and what the tests check.

## The standing rule

Any change to persistence, acknowledgements, identity, retries or money
updates the transition contract (`docs/contracts.md`: the promise, the
state table, the invariants) and its failure tests in the same commit.
"Persistence" is anything under `DATA_DIR`. "Acknowledgement" is the
`received` reply and every log line another tool reads. "Identity" is a
fingerprint, a payment hash, a preimage. "Retries" is every pass of the
buyer and the upgrader. "Money" is the ledger, the sidecars and every
`payinvoice` call.

A fix starts with the failing test: the defect reproduced under the
assertion the contract requires, red on the code before the fix, green
after. Interruption and concurrency cases sit beside the happy path for
every transition that has one. A test that injects an exception says so;
it is not a power cut. Integration tests wait for the whole postcondition
they assert (the log line the transition ends with), never for a file
that appears midway.

## Running the suite

```
python3 -m unittest discover -v
```

Standard library only for the adapter itself; the suite needs the
`opentimestamps` package, the parser corpus's oracle, and fails without
it rather than skipping.

## Commits

One change per commit, a message that says what changed and why, no
trailers.
