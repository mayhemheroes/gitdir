FROM golang:1.17 as builder

COPY . /gitdir
WORKDIR /gitdir/mayhem

RUN go install github.com/dvyukov/go-fuzz/go-fuzz@latest github.com/dvyukov/go-fuzz/go-fuzz-build@latest
RUN go get github.com/dvyukov/go-fuzz/go-fuzz-dep
RUN go get github.com/AdaLogics/go-fuzz-headers
RUN apt update && apt install -y clang

RUN go-fuzz-build -libfuzzer -o fuzzgitdir.a && \
    clang -fsanitize=fuzzer fuzzgitdir.a -o fuzzgitdir.libfuzzer

FROM debian:bookworm-slim
COPY --from=builder /gitdir/mayhem/fuzzgitdir.libfuzzer /