import chromadb
from chromadb.utils import embedding_functions
import os

CHROMA_PATH = "./chroma_db"
COLLECTION_NAME = "incident_runbooks"
EMBEDDING_MODEL = "all-MiniLM-L6-v2"


def get_collection():
    client = chromadb.PersistentClient(path=CHROMA_PATH)
    ef = embedding_functions.SentenceTransformerEmbeddingFunction(
        model_name=EMBEDDING_MODEL
    )
    collection = client.get_or_create_collection(
        name=COLLECTION_NAME,
        embedding_function=ef,
        metadata={"hnsw:space": "cosine"},
    )
    return collection


def seed_knowledge_base():
    collection = get_collection()

    if collection.count() > 0:
        print(f"[KB] Already has {collection.count()} runbooks. Skipping seed.")
        return

    runbooks = [
        {
            "id": "rb-001",
            "title": "High CPU — Identify and Kill Runaway Process",
            "content": """
                Symptom: CPU usage above 85% sustained for more than 2 minutes.
                Step 1: Run 'top -bn1 | head -20' to identify the top CPU consuming process.
                Step 2: Check if it is a known service (nginx, postgres, java) or an unknown PID.
                Step 3: If it is a known service behaving abnormally, restart it: 'systemctl restart <service>'.
                Step 4: If it is an unknown process, capture its command with 'ps aux | grep <PID>' then kill it: 'kill -9 <PID>'.
                Step 5: Monitor CPU for 2 minutes after action. If it stays high, escalate.
                Resolution: CPU should drop below 70% within 60 seconds of killing the process.
            """,
            "tags": "cpu high-cpu runaway-process performance",
        },
        {
            "id": "rb-002",
            "title": "Memory Exhaustion — Clear Cache and Restart Services",
            "content": """
                Symptom: Memory usage above 90%, risk of OOM kill.
                Step 1: Check memory consumers: 'ps aux --sort=-%mem | head -10'.
                Step 2: Drop page cache safely: 'sync && echo 3 > /proc/sys/vm/drop_caches'.
                Step 3: If memory is still critical, identify the top process and restart it.
                Step 4: Check for memory leaks — if the same service keeps growing, flag for Problem Resolver.
                Step 5: Verify memory drops below 80% within 2 minutes.
                Caution: Do not kill database processes without DBA approval.
            """,
            "tags": "memory oom memory-leak ram exhaustion",
        },
        {
            "id": "rb-003",
            "title": "PostgreSQL Down — Recovery Procedure",
            "content": """
                Symptom: PostgreSQL service not responding, connection refused on port 5432.
                Step 1: Check service status: 'systemctl status postgresql'.
                Step 2: Check PostgreSQL logs: 'tail -50 /var/log/postgresql/postgresql-*.log'.
                Step 3: Common cause A — disk full. Check: 'df -h'. If full, clean old WAL logs.
                Step 4: Common cause B — max connections exceeded. Restart: 'systemctl restart postgresql'.
                Step 5: Common cause C — corrupt data file. DO NOT restart. Escalate to DBA immediately.
                Step 6: After restart, verify: 'pg_isready -h localhost'.
                Resolution: Service should be accepting connections within 30 seconds.
            """,
            "tags": "postgresql database postgres down connection-refused db",
        },
        {
            "id": "rb-004",
            "title": "Nginx / Web Server Not Responding",
            "content": """
                Symptom: HTTP requests timing out, 502/504 errors, nginx process not responding.
                Step 1: Check nginx status: 'systemctl status nginx'.
                Step 2: Check nginx error log: 'tail -30 /var/log/nginx/error.log'.
                Step 3: Test config validity before restarting: 'nginx -t'.
                Step 4: If config is valid, restart: 'systemctl restart nginx'.
                Step 5: If config test fails, check recent config changes in /etc/nginx/sites-enabled/.
                Step 6: Verify recovery: 'curl -I http://localhost' should return 200.
            """,
            "tags": "nginx web-server http 502 504 upstream timeout",
        },
        {
            "id": "rb-005",
            "title": "Disk Space Critical — Emergency Cleanup",
            "content": """
                Symptom: Disk usage above 90%, services may start failing.
                Step 1: Find what is consuming space: 'du -sh /* 2>/dev/null | sort -rh | head -10'.
                Step 2: Safe cleanup targets:
                    - Old log files: 'find /var/log -name "*.gz" -mtime +7 -delete'
                    - Docker unused images: 'docker system prune -f'
                    - Old apt cache: 'apt-get clean'
                Step 3: Do NOT delete application data or database files without approval.
                Step 4: Verify disk drops below 80%: 'df -h'.
                Step 5: If still critical after cleanup, escalate — storage expansion needed.
            """,
            "tags": "disk disk-full storage space cleanup logs",
        },
        {
            "id": "rb-006",
            "title": "High Network Latency — Diagnosis Steps",
            "content": """
                Symptom: Network latency above 200ms, packet loss detected.
                Step 1: Check network interface stats: 'ifstat 1 5'.
                Step 2: Check for packet loss: 'ping -c 20 <gateway_ip>'.
                Step 3: Check if a single process is saturating bandwidth: 'iftop'.
                Step 4: Check for network errors: 'ip -s link'.
                Step 5: If a single process is saturating bandwidth, throttle or restart it.
                Step 6: If packet loss is 100%, escalate to network team — physical fault likely.
            """,
            "tags": "network latency packet-loss bandwidth slow connectivity",
        },
        {
            "id": "rb-007",
            "title": "Redis Cache Down or Not Responding",
            "content": """
                Symptom: Redis connection refused, application cache misses spiking.
                Step 1: Check Redis status: 'systemctl status redis'.
                Step 2: Check Redis log: 'tail -20 /var/log/redis/redis-server.log'.
                Step 3: Common cause — Redis ran out of memory. Check: 'redis-cli info memory'.
                Step 4: If maxmemory is hit, flush volatile keys only.
                Step 5: Restart if needed: 'systemctl restart redis'.
                Step 6: Verify: 'redis-cli ping' should return PONG.
                Caution: Do not FLUSHALL in production.
            """,
            "tags": "redis cache down memory connection refused",
        },
        {
            "id": "rb-008",
            "title": "JVM Heap Exhaustion — Java Application OOM",
            "content": """
                Symptom: Java process throwing OutOfMemoryError, application unresponsive.
                Step 1: Check heap usage: 'jstat -gcutil <PID> 1000 5'.
                Step 2: Take a heap dump before restarting: 'jmap -dump:format=b,file=/tmp/heap.hprof <PID>'.
                Step 3: Restart the Java service: 'systemctl restart <service>'.
                Step 4: If heap dumps show same objects growing, flag for Problem Resolver — memory leak likely.
                Step 5: Consider increasing heap size in JVM args: '-Xmx4g' if server has available RAM.
                Caution: Always take heap dump before restart to preserve evidence for root cause analysis.
            """,
            "tags": "java jvm heap oom outofmemory memory leak application",
        },
        {
            "id": "rb-009",
            "title": "Docker Container OOM Killed",
            "content": """
                Symptom: Docker container repeatedly restarting, OOM kill in kernel logs.
                Step 1: Check container status: 'docker ps -a | grep <container>'.
                Step 2: Check OOM kill evidence: 'dmesg | grep -i oom | tail -20'.
                Step 3: Check container memory limit: 'docker inspect <container> | grep -i memory'.
                Step 4: Check container memory usage before kill: 'docker stats --no-stream'.
                Step 5: If container has no memory limit set, add one: 'docker update --memory 2g <container>'.
                Step 6: If container has limit set and still OOM, the app needs optimization — escalate.
                Step 7: Restart container: 'docker restart <container>'.
                Resolution: Container should stay running. If it OOMs again within 10 mins, escalate.
            """,
            "tags": "docker container oom killed restart memory limit",
        },
        {
            "id": "rb-010",
            "title": "High Process Count — Fork Bomb or Runaway Spawning",
            "content": """
                Symptom: Process count above 500, system sluggish, fork errors in logs.
                Step 1: Count processes: 'ps aux | wc -l'.
                Step 2: Find process spawning children: 'ps --ppid <PID> | wc -l' for top processes.
                Step 3: Check ulimit for max processes: 'ulimit -u'.
                Step 4: If a single parent is spawning hundreds of children, kill the parent: 'kill -9 <PID>'.
                Step 5: If it looks like a fork bomb, kill all processes from that user: 'pkill -u <username>'.
                Step 6: After cleanup, verify process count returns to normal: 'ps aux | wc -l'.
                Caution: Do not kill system processes. Verify PID belongs to application user first.
            """,
            "tags": "process fork bomb high process count spawning ulimit",
        },
        {
            "id": "rb-011",
            "title": "Swap Memory Exhaustion",
            "content": """
                Symptom: Swap usage above 80%, system extremely slow, thrashing.
                Step 1: Verify swap exhaustion: 'free -h' and 'swapon --show'.
                Step 2: Check what is using swap: 'for f in /proc/*/status; do awk -v PID=${f%/status} -v PID=${f#/proc/} /VmSwap/{print PID, $2, $3} $f; done | sort -k2 -n -r | head -10'.
                Step 3: Identify top swap consumer and restart it if it is a known service.
                Step 4: Clear swap temporarily: 'swapoff -a && swapon -a' (WARNING: requires free RAM).
                Step 5: If RAM is also near exhaustion, do NOT clear swap — escalate immediately.
                Step 6: After clearing, monitor swap usage for 5 minutes.
                Caution: Never clear swap if RAM usage is above 85% — will cause immediate OOM.
            """,
            "tags": "swap memory exhaustion thrashing virtual memory",
        },
        {
            "id": "rb-012",
            "title": "Windows Service Crash — Recovery Procedure",
            "content": """
                Symptom: Windows service stopped unexpectedly, Event Viewer shows error.
                Step 1: Check service status: 'Get-Service <ServiceName>' in PowerShell.
                Step 2: Check Event Viewer: 'Get-EventLog -LogName Application -Newest 20 | Where-Object {$_.EntryType -eq Error}'.
                Step 3: Attempt restart: 'Restart-Service <ServiceName>'.
                Step 4: If restart fails, check dependencies: 'Get-Service <ServiceName> | Select-Object -ExpandProperty DependentServices'.
                Step 5: Ensure dependent services are running first, then retry main service restart.
                Step 6: If service keeps crashing within 5 minutes, check application logs and escalate.
                Resolution: Service should show Running status after restart.
            """,
            "tags": "windows service crash restart powershell event viewer",
        },
        {
            "id": "rb-013",
            "title": "Port Exhaustion — Too Many TIME_WAIT Connections",
            "content": """
                Symptom: Application cannot open new connections, port exhaustion errors in logs.
                Step 1: Count TIME_WAIT connections: 'ss -tan | grep TIME-WAIT | wc -l'.
                Step 2: If above 10000, port exhaustion is the likely cause.
                Step 3: Reduce TIME_WAIT timeout: 'echo 30 > /proc/sys/net/ipv4/tcp_fin_timeout'.
                Step 4: Enable TIME_WAIT socket reuse: 'echo 1 > /proc/sys/net/ipv4/tcp_tw_reuse'.
                Step 5: Expand local port range: 'echo "1024 65535" > /proc/sys/net/ipv4/ip_local_port_range'.
                Step 6: Restart the application service to clear its connection pool.
                Step 7: Verify new connections can be established after fix.
                Note: These are runtime fixes — make permanent in /etc/sysctl.conf.
            """,
            "tags": "port exhaustion time_wait connections tcp network socket",
        },
        {
            "id": "rb-014",
            "title": "DNS Resolution Failure",
            "content": """
                Symptom: Services cannot connect to external hosts, DNS lookup failures in logs.
                Step 1: Test DNS resolution: 'nslookup google.com' and 'dig google.com'.
                Step 2: Check /etc/resolv.conf for correct nameserver entries.
                Step 3: Test direct connectivity to DNS server: 'ping <nameserver_ip>'.
                Step 4: If DNS server unreachable, add a fallback: 'echo "nameserver 8.8.8.8" >> /etc/resolv.conf'.
                Step 5: Restart systemd-resolved if used: 'systemctl restart systemd-resolved'.
                Step 6: Flush DNS cache: 'systemd-resolve --flush-caches'.
                Step 7: Verify resolution works: 'nslookup google.com'.
                Note: If internal DNS is down, escalate to network team — affects entire infrastructure.
            """,
            "tags": "dns resolution failure nameserver lookup network connectivity",
        },
        {
            "id": "rb-015",
            "title": "SSL Certificate Expiry Warning",
            "content": """
                Symptom: SSL certificate expiring within 30 days, HTTPS warnings appearing.
                Step 1: Check certificate expiry: 'echo | openssl s_client -connect <hostname>:443 2>/dev/null | openssl x509 -noout -dates'.
                Step 2: Check all certificates on the server: 'find /etc/ssl /etc/nginx /etc/apache2 -name "*.crt" -o -name "*.pem" 2>/dev/null'.
                Step 3: For Let's Encrypt: 'certbot renew --dry-run' to test renewal.
                Step 4: Renew if dry run succeeds: 'certbot renew'.
                Step 5: Reload web server after renewal: 'systemctl reload nginx' or 'systemctl reload apache2'.
                Step 6: Verify new expiry date after renewal.
                Caution: Certificate expiry causes immediate service outage. Treat as P1 if expiry within 7 days.
            """,
            "tags": "ssl certificate expiry https tls renewal lets encrypt",
        },
    ]

    print(f"[KB] Seeding knowledge base with {len(runbooks)} runbooks...")
    collection.add(
        ids=[r["id"] for r in runbooks],
        documents=[r["content"] for r in runbooks],
        metadatas=[{"title": r["title"], "tags": r["tags"]} for r in runbooks],
    )
    print(f"[KB] Done. Knowledge base ready.")


def query_knowledge_base(query: str, n_results: int = 3) -> list[dict]:
    collection = get_collection()

    if collection.count() == 0:
        return []

    results = collection.query(
        query_texts=[query],
        n_results=min(n_results, collection.count()),
    )

    matches = []
    for i in range(len(results["ids"][0])):
        matches.append({
            "id": results["ids"][0][i],
            "title": results["metadatas"][0][i]["title"],
            "content": results["documents"][0][i].strip(),
            "score": round(1 - results["distances"][0][i], 3),
        })

    return matches