import json
import socket
import ssl
import statistics
import threading
import time
from collections import Counter
from urllib.parse import urlparse

import httpx

from .config import load_engine
from .roe_guard import ROEGuard, ROEViolation
from . import http as _http

try:
    import h2.connection
    import h2.config
    import h2.events
    HAS_H2 = True
except ImportError:
    HAS_H2 = False


SUCCESS_CODES = {200, 201, 202, 204}
DEFAULT_COUNT = 20
DEFAULT_TIMEOUT = 15


def _verify_tls():
    try:
        cfg = load_engine() or {}
        return bool(cfg.get("http", {}).get("verify_tls", True))
    except Exception:
        return True


def _roe_block(guard, url, method="POST"):
    if guard is None:
        try:
            guard = ROEGuard(engine_cfg=load_engine())
        except Exception as e:
            return f"ROE guard unavailable (fail-closed): {e}"
    try:
        guard.check_url(url, method)
        return None
    except ROEViolation as e:
        return str(e)


def _analyze_statuses(results, count):
    statuses = Counter()
    for r in results:
        s = r.get("status")
        if s is not None:
            statuses[str(s)] += 1
    success_count = sum(c for s, c in statuses.items()
                        if int(s) in SUCCESS_CODES)
    timings = [r["time_ms"] for r in results if r.get("time_ms") is not None]
    return {
        "statuses": dict(statuses),
        "success_count": success_count,
        "total": count,
        "timings_ms": timings,
        "timing_mean_ms": round(statistics.mean(timings), 2) if timings else None,
        "timing_stdev_ms": round(statistics.pstdev(timings), 2) if len(timings) > 1 else None,
    }


def _judge_outcome(analysis):
    sc = analysis["success_count"]
    total = analysis["total"]
    if sc > 1:
        return {
            "verdict": "VULNERABLE",
            "reason": f"{sc}/{total} requests succeeded simultaneously "
                      f"(invariant violated: only 1 should be allowed)",
            "evidence": analysis,
        }
    if sc == 1:
        return {
            "verdict": "PASS",
            "reason": f"exactly 1/{total} succeeded (properly guarded)",
            "evidence": analysis,
        }
    statuses = analysis.get("statuses") or {}
    errors = analysis.get("errors") or []
    responded = sum(statuses.values())
    if responded == 0:
        first = errors[0] if errors else "no response"
        return {
            "verdict": "UNKNOWN",
            "reason": f"target unreachable: {first[:140]}",
            "evidence": analysis,
        }
    if sc == 0 and any(k in ("401", "403") for k in statuses):
        return {
            "verdict": "UNKNOWN",
            "reason": "all requests rejected with auth error; cannot test race",
            "evidence": analysis,
        }
    if sc == 0 and all(int(k) >= 500 for k in statuses):
        return {
            "verdict": "UNKNOWN",
            "reason": f"all {responded} responses were 5xx errors; cannot test race",
            "evidence": analysis,
        }
    if sc == 0 and statuses:
        codes = ", ".join(sorted(statuses.keys()))
        return {
            "verdict": "PASS",
            "reason": f"0/{total} succeeded (all responses {codes})",
            "evidence": analysis,
        }
    return {
        "verdict": "UNKNOWN",
        "reason": "no usable responses",
        "evidence": analysis,
    }


def barrier_race(url, method="POST", body=None, headers=None, count=DEFAULT_COUNT,
                 timeout=DEFAULT_TIMEOUT, roe_guard=None, verify_tls=None):
    if verify_tls is None:
        verify_tls = _verify_tls()
    viol = _roe_block(roe_guard, url, method)
    if viol:
        return {"verdict": "UNKNOWN", "reason": f"ROE_BLOCK: {viol}", "evidence": {}}

    barrier = threading.Barrier(count, timeout=timeout)
    results = []
    lock = threading.Lock()

    def fire():
        client = _http.Client(timeout=timeout, verify=verify_tls,
                              follow_redirects=False)
        try:
            try:
                client.head(url, timeout=5)
            except Exception:
                pass
            barrier.wait()
            t0 = time.perf_counter()
            kwargs = {"headers": headers or {}, "skip_rate_limit": True}
            if body is not None:
                if isinstance(body, dict):
                    kwargs["json"] = body
                else:
                    kwargs["data"] = body
            r = client.request(method.upper(), url, **kwargs)
            elapsed = (time.perf_counter() - t0) * 1000
            with lock:
                results.append({"status": r.status_code,
                                "time_ms": round(elapsed, 2),
                                "body_len": len(r.text or "")})
        except threading.BrokenBarrierError:
            with lock:
                results.append({"status": None, "time_ms": None,
                                "error": "barrier timeout"})
        except Exception as e:
            with lock:
                results.append({"status": None, "time_ms": None,
                                "error": f"{type(e).__name__}: {e}"})
        finally:
            client.close()

    threads = [threading.Thread(target=fire, daemon=True) for _ in range(count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=timeout + 5)

    analysis = _analyze_statuses(results, count)
    analysis["errors"] = [r["error"] for r in results if r.get("error")]
    verdict = _judge_outcome(analysis)
    verdict["evidence"]["method"] = "barrier"
    return verdict


def _h2_connect(host, port, use_tls, verify_tls, timeout):
    try:
        ctx = ssl.create_default_context()
        if not verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2"])
        raw = socket.create_connection((host, port), timeout=timeout)
        if use_tls:
            sock = ctx.wrap_socket(raw, server_hostname=host)
            negotiated = sock.selected_alpn_protocol()
            if negotiated != "h2":
                sock.close()
                return None, None, f"server did not negotiate h2 (got {negotiated!r})"
            return sock, None, None
        return raw, None, None
    except ConnectionRefusedError:
        return None, None, "connection refused (target not listening)"
    except socket.timeout:
        return None, None, f"connection timed out after {timeout}s"
    except OSError as e:
        return None, None, f"network error: {e}"
    except Exception as e:
        return None, None, f"{type(e).__name__}: {e}"


def single_packet_attack(url, method="POST", body=None, headers=None,
                         count=DEFAULT_COUNT, timeout=DEFAULT_TIMEOUT,
                         roe_guard=None, verify_tls=None):
    if not HAS_H2:
        return {"verdict": "UNKNOWN",
                "reason": "h2 library not installed (pip install h2)",
                "evidence": {}}
    if verify_tls is None:
        verify_tls = _verify_tls()
    viol = _roe_block(roe_guard, url, method)
    if viol:
        return {"verdict": "UNKNOWN", "reason": f"ROE_BLOCK: {viol}", "evidence": {}}

    parsed = urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    use_tls = parsed.scheme == "https"
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    if body is None:
        body_bytes = b""
    elif isinstance(body, dict):
        body_bytes = json.dumps(body).encode()
    else:
        body_bytes = str(body).encode()

    h2_headers = [
        (":method", method.upper()),
        (":authority", host),
        (":scheme", "https" if use_tls else "http"),
        (":path", path),
    ]
    if body_bytes:
        h2_headers.append(("content-type", "application/json"))
        h2_headers.append(("content-length", str(len(body_bytes))))
    if headers:
        for k, v in headers.items():
            h2_headers.append((k.lower(), str(v)))

    if use_tls:
        pass
    sock, _, err = _h2_connect(host, port, use_tls, verify_tls, timeout)
    if err:
        return {"verdict": "UNKNOWN",
                "reason": f"HTTP/2 single-packet attack not available: {err}",
                "evidence": {"method": "single_packet", "error": err}}

    try:
        config = h2.config.H2Configuration(client_side=True)
        conn = h2.connection.H2Connection(config=config)
        conn.initiate_connection()
        sock.sendall(conn.data_to_send())

        sock.settimeout(timeout)
        try:
            data = sock.recv(65535)
            if data:
                conn.receive_data(data)
                sock.sendall(conn.data_to_send())
        except socket.timeout:
            pass

        stream_ids = []
        for _ in range(count):
            sid = conn.get_next_available_stream_id()
            stream_ids.append(sid)
            conn.send_headers(sid, h2_headers, end_stream=False)
        sock.sendall(conn.data_to_send())

        if body_bytes:
            for sid in stream_ids:
                conn.send_data(sid, body_bytes, end_stream=False)
            sock.sendall(conn.data_to_send())

        time.sleep(0.1)

        try:
            sock.settimeout(0.05)
            while True:
                chunk = sock.recv(65535)
                if not chunk:
                    break
                conn.receive_data(chunk)
        except socket.timeout:
            pass

        for sid in stream_ids:
            conn.send_data(sid, b"", end_stream=True)

        t0 = time.perf_counter()
        sock.sendall(conn.data_to_send())

        sock.settimeout(timeout)
        responses = {}
        pending = set(stream_ids)
        deadline = time.monotonic() + timeout
        while pending and time.monotonic() < deadline:
            try:
                data = sock.recv(65535)
            except socket.timeout:
                break
            if not data:
                break
            events = conn.receive_data(data)
            for ev in events:
                if isinstance(ev, h2.events.ResponseReceived):
                    sid = ev.stream_id
                    status = dict(ev.headers).get(":status")
                    responses[sid] = {"status": int(status) if status else None}
                elif isinstance(ev, h2.events.DataReceived):
                    conn.acknowledge_received_data(ev.flow_controlled_length,
                                                   ev.stream_id)
                elif isinstance(ev, (h2.events.StreamEnded, h2.events.StreamReset)):
                    pending.discard(ev.stream_id)
            out = conn.data_to_send()
            if out:
                sock.sendall(out)

        elapsed = (time.perf_counter() - t0) * 1000

        results = [{"status": responses.get(sid, {}).get("status"),
                    "time_ms": None} for sid in stream_ids]
        if not any(r["status"] is not None for r in results):
            return {"verdict": "UNKNOWN",
                    "reason": "no responses received from single-packet burst "
                              "(server may not support HTTP/2 or reset the connection)",
                    "evidence": {"elapsed_ms": round(elapsed, 2)}}

        analysis = _analyze_statuses(results, count)
        analysis["elapsed_ms"] = round(elapsed, 2)
        verdict = _judge_outcome(analysis)
        verdict["evidence"]["method"] = "single_packet"
        return verdict
    except Exception as e:
        return {"verdict": "UNKNOWN",
                "reason": f"single-packet attack error: {type(e).__name__}: {e}",
                "evidence": {}}
    finally:
        try:
            sock.close()
        except Exception:
            pass


def timing_histogram(url, method="POST", body=None, headers=None,
                     count=20, rounds=3, timeout=DEFAULT_TIMEOUT,
                     roe_guard=None, verify_tls=None):
    if verify_tls is None:
        verify_tls = _verify_tls()
    viol = _roe_block(roe_guard, url, method)
    if viol:
        return {"verdict": "UNKNOWN", "reason": f"ROE_BLOCK: {viol}", "evidence": {}}

    per_round = []
    for _ in range(rounds):
        barrier = threading.Barrier(count, timeout=timeout)
        results = []
        lock = threading.Lock()

        def fire():
            client = _http.Client(timeout=timeout, verify=verify_tls,
                                  follow_redirects=False)
            try:
                try:
                    client.head(url, timeout=5)
                except Exception:
                    pass
                barrier.wait()
                t0 = time.perf_counter()
                kwargs = {"headers": headers or {}, "skip_rate_limit": True}
                if body is not None:
                    if isinstance(body, dict):
                        kwargs["json"] = body
                    else:
                        kwargs["data"] = body
                r = client.request(method.upper(), url, **kwargs)
                elapsed = (time.perf_counter() - t0) * 1000
                with lock:
                    results.append({"status": r.status_code,
                                    "time_ms": round(elapsed, 3)})
            except Exception:
                with lock:
                    results.append({"status": None, "time_ms": None})
            finally:
                client.close()

        threads = [threading.Thread(target=fire, daemon=True)
                   for _ in range(count)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=timeout + 5)
        per_round.append(results)

    all_timings = []
    for rnd in per_round:
        for r in rnd:
            if r.get("time_ms") is not None:
                all_timings.append(r["time_ms"])

    if len(all_timings) < 5:
        return {"verdict": "UNKNOWN",
                "reason": f"only {len(all_timings)} successful timings; "
                          f"need >= 5 for histogram analysis",
                "evidence": {"samples": len(all_timings)}}

    all_timings.sort()
    n = len(all_timings)
    mean = statistics.mean(all_timings)
    stdev = statistics.pstdev(all_timings)
    p50 = all_timings[n // 2]
    p95 = all_timings[min(int(n * 0.95), n - 1)]
    p99 = all_timings[min(int(n * 0.99), n - 1)]

    q1 = all_timings[n // 4]
    q3 = all_timings[(3 * n) // 4]
    iqr = q3 - q1

    bimodal = False
    if iqr > 0 and n >= 10:
        gap_threshold = q3 + 1.5 * iqr
        slow_tail = [t for t in all_timings if t > gap_threshold]
        if len(slow_tail) >= 2 and (slow_tail[0] - q3) > 2 * iqr:
            bimodal = True

    evidence = {
        "samples": n,
        "mean_ms": round(mean, 2),
        "stdev_ms": round(stdev, 2),
        "p50_ms": round(p50, 2),
        "p95_ms": round(p95, 2),
        "p99_ms": round(p99, 2),
        "iqr_ms": round(iqr, 2),
        "bimodal_detected": bimodal,
        "method": "timing_histogram",
    }

    if bimodal:
        return {"verdict": "SUSPICIOUS",
                "reason": f"bimodal timing distribution detected "
                          f"(p50={p50:.0f}ms, p99={p99:.0f}ms, "
                          f"stdev={stdev:.1f}ms) — possible contention window",
                "evidence": evidence}
    if stdev > mean * 0.5 and mean > 20:
        return {"verdict": "SUSPICIOUS",
                "reason": f"high timing variance (mean={mean:.0f}ms, "
                          f"stdev={stdev:.1f}ms) — possible server-side contention",
                "evidence": evidence}
    return {"verdict": "PASS",
            "reason": f"unimodal timing (mean={mean:.0f}ms, stdev={stdev:.1f}ms)",
            "evidence": evidence}


def state_machine_replay(url, method="POST", body=None, headers=None,
                         timeout=DEFAULT_TIMEOUT, roe_guard=None,
                         verify_tls=None):
    if verify_tls is None:
        verify_tls = _verify_tls()
    viol = _roe_block(roe_guard, url, method)
    if viol:
        return {"verdict": "UNKNOWN", "reason": f"ROE_BLOCK: {viol}", "evidence": {}}

    def do_request():
        client = _http.Client(timeout=timeout, verify=verify_tls,
                              follow_redirects=False)
        try:
            kwargs = {"headers": headers or {}}
            if body is not None:
                if isinstance(body, dict):
                    kwargs["json"] = body
                else:
                    kwargs["data"] = body
            r = client.request(method.upper(), url, **kwargs)
            return {"status": r.status_code, "body": (r.text or "")[:500]}
        finally:
            client.close()

    try:
        first = do_request()
    except Exception as e:
        return {"verdict": "UNKNOWN",
                "reason": f"first request failed: {type(e).__name__}: {e}",
                "evidence": {}}

    if first["status"] is None or first["status"] >= 500:
        return {"verdict": "UNKNOWN",
                "reason": f"first request returned HTTP {first['status']}; "
                          f"cannot test replay",
                "evidence": {"first": first}}

    time.sleep(0.3)

    try:
        second = do_request()
    except Exception as e:
        return {"verdict": "UNKNOWN",
                "reason": f"second request failed: {type(e).__name__}: {e}",
                "evidence": {"first": first}}

    evidence = {
        "first_status": first["status"],
        "second_status": second["status"],
        "method": "state_machine_replay",
    }

    first_ok = first["status"] in SUCCESS_CODES
    second_ok = second["status"] in SUCCESS_CODES

    if first_ok and second_ok:
        return {"verdict": "VULNERABLE",
                "reason": f"same request succeeded twice "
                          f"(HTTP {first['status']} then {second['status']}) — "
                          f"missing idempotency guard",
                "evidence": evidence}
    if first_ok and not second_ok:
        return {"verdict": "PASS",
                "reason": f"second replay rejected (HTTP {second['status']}) — "
                          f"properly guarded",
                "evidence": evidence}
    return {"verdict": "PASS",
            "reason": f"neither request succeeded as a state change "
                      f"(HTTP {first['status']}, {second['status']})",
            "evidence": evidence}


def _race_scan_impl(url, method="POST", body=None, headers=None, count=DEFAULT_COUNT,
              modes=None, timeout=DEFAULT_TIMEOUT, roe_guard=None,
              verify_tls=None):
    if verify_tls is None:
        verify_tls = _verify_tls()
    if modes is None:
        modes = ["barrier", "single_packet", "timing", "replay"]

    results = {}
    if "barrier" in modes:
        try:
            results["barrier"] = barrier_race(
                url, method=method, body=body, headers=headers, count=count,
                timeout=timeout, roe_guard=roe_guard, verify_tls=verify_tls)
        except Exception as e:
            results["barrier"] = {"verdict": "UNKNOWN",
                                  "reason": f"{type(e).__name__}: {e}",
                                  "evidence": {}}
    if "single_packet" in modes:
        try:
            results["single_packet"] = single_packet_attack(
                url, method=method, body=body, headers=headers, count=count,
                timeout=timeout, roe_guard=roe_guard, verify_tls=verify_tls)
        except Exception as e:
            results["single_packet"] = {"verdict": "UNKNOWN",
                                        "reason": f"{type(e).__name__}: {e}",
                                        "evidence": {}}
    if "timing" in modes:
        try:
            results["timing"] = timing_histogram(
                url, method=method, body=body, headers=headers, count=count,
                rounds=3, timeout=timeout, roe_guard=roe_guard, verify_tls=verify_tls)
        except Exception as e:
            results["timing"] = {"verdict": "UNKNOWN",
                                 "reason": f"{type(e).__name__}: {e}",
                                 "evidence": {}}
    if "replay" in modes:
        try:
            results["replay"] = state_machine_replay(
                url, method=method, body=body, headers=headers,
                timeout=timeout, roe_guard=roe_guard, verify_tls=verify_tls)
        except Exception as e:
            results["replay"] = {"verdict": "UNKNOWN",
                                 "reason": f"{type(e).__name__}: {e}",
                                 "evidence": {}}

    rank = {"VULNERABLE": 3, "SUSPICIOUS": 2, "PASS": 1, "UNKNOWN": 0}
    overall = "UNKNOWN"
    for r in results.values():
        if rank.get(r.get("verdict"), 0) > rank.get(overall, 0):
            overall = r["verdict"]

    return {"url": url, "method": method.upper(), "count": count,
            "overall": overall, "results": results}

def race_scan(*args, **kwargs):
    from .contract import make_result
    raw = _race_scan_impl(*args, **kwargs)
    return make_result(raw, capability="race_advanced", args=args, kwargs=kwargs)
