FROM neotheprogramist/prover:latest

COPY src/main.cairo .
RUN cairo-compile \
    --proof_mode \
    --output program_compiled.json \
    main.cairo

ENTRYPOINT [ "prover-entrypoint.sh" ]
