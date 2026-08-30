#!/bin/sh
# The overread gate. Run it as `make overread`.
#
# It builds a second binary with the plant_overread feature, which
# plants a read one
# past the end of the file buffer, and fails unless that read is caught
# at the index it was made at. With the plant compiled out the same
# command must succeed, so the gate cannot pass by the binary being
# broken in some other way.
set -u
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(dirname "$HERE")
PLANTED=$ROOT/target/overread/release/certlint
PLAIN=$ROOT/target/release/certlint
IN=$ROOT/t/corpus/leaf-rsa.pem

[ -f "$IN" ] || { echo "overread: no corpus; run make test first" >&2; exit 2; }
[ -x "$PLANTED" ] || { echo "overread: $PLANTED was not built" >&2; exit 2; }

"$PLAIN" --dump "$IN" >/dev/null 2>&1
rc=$?
if [ $rc -ne 0 ]; then
    echo "overread: the ordinary binary exited $rc on $IN, so the planted" \
         "run proves nothing" >&2
    exit 2
fi

err=$("$PLANTED" --dump "$IN" 2>&1 >/dev/null)
rc=$?
size=$(wc -c < "$IN" | tr -d ' ')
if [ $rc -ne 134 ]; then
    echo "overread: the planted read exited $rc, wanted 134" >&2
    echo "$err" >&2
    exit 1
fi
case "$err" in
    *"index out of bounds: the len is $size but the index is $size"*) ;;
    *)
        echo "overread: the panic did not name index $size:" >&2
        echo "$err" >&2
        exit 1
        ;;
esac
echo "overread: the planted read of index $size is caught at index $size"
echo "1 passed, 0 failed"
