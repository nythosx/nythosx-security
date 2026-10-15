import threading

from engine.facts import FactStore


def test_concurrent_adds_no_crash():
    store = FactStore()

    def writer(i):
        for j in range(100):
            store.add(f"key_{i}", j, source="active_probe")

    threads = [threading.Thread(target=writer, args=(i,)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    for i in range(20):
        assert store.has(f"key_{i}")


def test_concurrent_reads_and_writes_no_crash():
    store = FactStore()
    stop = threading.Event()
    errors = []

    def writer():
        i = 0
        while not stop.is_set():
            store.add("shared", i, source="active_probe")
            i += 1

    def reader():
        try:
            for _ in range(2000):
                store.get("shared")
                store.has("shared")
                store.keys()
        except Exception as e:
            errors.append(e)

    writers = [threading.Thread(target=writer) for _ in range(4)]
    readers = [threading.Thread(target=reader) for _ in range(4)]
    for t in writers + readers:
        t.start()
    for t in readers:
        t.join()
    stop.set()
    for t in writers:
        t.join()

    assert not errors


def test_concurrent_higher_confidence_wins():
    store = FactStore()

    def writer(value, source):
        for _ in range(200):
            store.add("shared", value, source=source)

    t1 = threading.Thread(target=writer, args=("low", "js_match"))
    t2 = threading.Thread(target=writer, args=("high", "live_confirm"))
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    assert store.get("shared") == "high"
