FROM python:3.9.18

RUN pip install --upgrade pip
RUN pip install cairo-lang==0.12.3

COPY pie-entrypoint.sh /bin/

COPY src/main.cairo .
RUN cairo-compile \
    --proof_mode \
    --output program_compiled.json \
    main.cairo

ENTRYPOINT [ "pie-entrypoint.sh" ]
