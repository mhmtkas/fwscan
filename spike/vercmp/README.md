# T0.5 version-comparison harness

Cross-checks `knqyf263/go-deb-version` against `dpkg --compare-versions`, which is
the oracle. Nested module on purpose: the root module does not exist until T1, and
Go excludes a directory with its own `go.mod` from the parent's `./...` patterns.

    while read -r a b; do
      dpkg --compare-versions "$a" lt "$b" && echo "$a $b lt" && continue
      dpkg --compare-versions "$a" gt "$b" && echo "$a $b gt" || echo "$a $b eq"
    done < cases.txt > oracle.txt
    go run . < cases.txt > golib.txt
    diff oracle.txt golib.txt

Result at the time of the spike: 18/18 agree. The same table is carried into T6 as
a real table-driven unit test.
