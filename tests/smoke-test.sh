# Smoke test for the caddy-waf image: starts a test upstream and the image
# under podman (host network), then checks the WAF blocks attacks, honours
# exclusions, throttles logins by the real client address and keeps secrets
# out of the access log.
#
# Usage: smoke-test [image]   (default localhost/caddy-waf:latest)
# Needs podman on PATH and ports 8080/18081 free. KEEP=1 leaves the
# container running for debugging.

IMAGE="${1:-localhost/caddy-waf:latest}"
FIXTURES="${FIXTURES:-$(dirname "$0")/../tests/fixtures}"
[ -d "$FIXTURES" ] || FIXTURES="$(pwd)/tests/fixtures"
FIXTURES="$(realpath "$FIXTURES")"
NAME="caddy-waf-smoke-$$"
WAF=http://127.0.0.1:8080
failures=0

python3 "$FIXTURES/backend.py" 18081 &
backend=$!
cleanup() {
  kill "$backend" 2>/dev/null || true
  podman rm -f "$NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT
[ -n "${KEEP:-}" ] && trap - EXIT

podman run -d --name "$NAME" --network host \
  --read-only --tmpfs /tmp:mode=1777 \
  -e BACKEND=http://127.0.0.1:18081 \
  -e TRUSTED_PROXIES=127.0.0.0/8 \
  -e "ALLOWED_METHODS=GET HEAD POST OPTIONS PUT PATCH DELETE" \
  -v "$FIXTURES/rules:/etc/caddy-waf/rules:ro" \
  -v "$FIXTURES/site.d:/etc/caddy-waf/site.d:ro" \
  "$IMAGE" >/dev/null

for _ in $(seq 1 50); do
  curl -sf -o /dev/null "http://127.0.0.1:8080/healthz" && break
  sleep 0.2
done
if ! curl -sf -o /dev/null "$WAF/healthz"; then
  echo "FAIL caddy did not start:"
  podman logs "$NAME" 2>&1 | tail -n 20
  exit 1
fi

check() { # name expected actual
  if [ "$2" = "$3" ]; then
    echo "ok   $1 ($3)"
  else
    echo "FAIL $1: want $2, got $3"
    failures=$((failures + 1))
  fi
}
# Expect: empty, because curl sends "Expect: 100-continue" for bodies over
# 1 MB and CRS 920450 blocks that header (as it does under ModSecurity).
code() { curl -s -o /dev/null -w '%{http_code}' -H 'Expect:' "$@"; }

check "healthz" 200 "$(code "$WAF/healthz")"
check "benign GET" 200 "$(code "$WAF/hello?q=films")"
check "SQL injection in query" 403 "$(code "$WAF/hello?id=1%27%20OR%20%271%27%3D%271")"
check "path traversal in query" 403 "$(code "$WAF/hello?file=../../../../etc/passwd")"
check "XSS in query" 403 "$(code "$WAF/hello?q=%3Cscript%3Ealert(1)%3C/script%3E")"
check "scanner user agent" 403 "$(code -A 'sqlmap/1.8' "$WAF/hello")"
check "method not allowed (CRS 911100)" 403 "$(code -X TRACE "$WAF/hello")"
check "SQL in excluded password field" 200 \
  "$(code -X POST -H 'X-Forwarded-For: 203.0.113.50' -d "password=x' OR 1=1--" "$WAF/ui/login/password")"
check "SQL in non-excluded login field" 403 \
  "$(code -X POST -H 'X-Forwarded-For: 203.0.113.51' -d "loginName=x' OR 1=1--" "$WAF/ui/login/password")"
grpc_body="$(mktemp)"
printf '\x00\x00\x00\x00\x05select' >"$grpc_body"
check "binary body on token API skips inspection" 200 \
  "$(code -X POST -H 'Content-Type: application/grpc-web+proto' --data-binary @"$grpc_body" "$WAF/api.v1.Service/Call")"
check "oversized body rejected" 413 \
  "$(head -c 1100000 /dev/zero | tr '\0' a | code -X POST -H 'Content-Type: application/x-www-form-urlencoded' --data-binary @- "$WAF/hello")"
check "oversized JSON body rejected" 413 \
  "$(head -c 1100000 /dev/zero | tr '\0' a | code -X POST -H 'Content-Type: application/json' --data-binary @- "$WAF/hello")"
check "oversized chunked body rejected" 413 \
  "$(head -c 1100000 /dev/zero | tr '\0' a | code -X POST -H 'Transfer-Encoding: chunked' -H 'Content-Type: application/json' --data-binary @- "$WAF/hello")"
check "WAF block keeps its status after handle_errors" 403 "$(code "$WAF/hello?q=%3Cscript%3E")"
upload="$(mktemp)"
head -c 2000000 /dev/urandom >"$upload"
check "2 MB multipart upload allowed" 200 "$(code -F "file=@$upload" "$WAF/hello")"

headers="$(curl -s -H 'Host: app.example.test' "$WAF/hello")"
check "Host passed through" 1 "$(grep -c '"Host": "app.example.test"' <<<"$headers")"
check "X-Forwarded-Proto https upstream" 1 "$(grep -c '"X-Forwarded-Proto": "https"' <<<"$headers")"

# Throttle: 10 events per minute per client. The 11th from one client is
# throttled even when the client forges a different left-most XFF entry.
for i in $(seq 1 10); do
  code -X POST -H "X-Forwarded-For: 198.51.100.$i, 203.0.113.7" -d 'loginName=alice' "$WAF/ui/login/login" >/dev/null
done
check "11th login from one client throttled" 429 \
  "$(code -X POST -H 'X-Forwarded-For: 192.0.2.99, 203.0.113.7' -d 'loginName=alice' "$WAF/ui/login/login")"
check "another client not throttled" 200 \
  "$(code -X POST -H 'X-Forwarded-For: 203.0.113.8' -d 'loginName=alice' "$WAF/ui/login/login")"
check "non-login POST not throttled" 200 \
  "$(code -X POST -H 'X-Forwarded-For: 203.0.113.7' -d 'a=b' "$WAF/hello")"

# Streaming: the first chunk must arrive before the upstream finishes (4 s).
first="$(curl -s -N --max-time 1 "$WAF/stream" || true)"
check "response streamed, not buffered" 1 "$(grep -c first <<<"$first")"

# Secrets in query strings and headers stay out of the access log.
curl -s -o /dev/null -H 'Referer: https://x.test/?code=refsecret' -H 'Authorization: Bearer hdrsecret' \
  "$WAF/hello?token=querysecret"
sleep 0.5
logs="$(podman logs "$NAME" 2>&1)"
check "query string not logged" 0 "$(grep -c querysecret <<<"$logs" || true)"
check "Referer not logged" 0 "$(grep -c refsecret <<<"$logs" || true)"
check "Authorization not logged" 0 "$(grep -c hdrsecret <<<"$logs" || true)"
check "audit log records blocks" 1 "$(grep -q '"transaction"' <<<"$logs" && echo 1 || echo 0)"

if [ "$failures" -ne 0 ]; then
  echo "$failures check(s) failed. Container logs:"
  tail -n 40 <<<"$logs"
  exit 1
fi
echo "all checks passed"
