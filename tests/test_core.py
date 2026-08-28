"""Offline test suite for the deception core.

Runs without Docker and without Ollama: the LLM client is replaced by a stub,
so these tests exercise exactly the deterministic layer -- the part that must
be correct and coherent regardless of what the model does.

    python tests/test_core.py

Exit code 0 means every assertion held.
"""
from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agents"))

os.environ.setdefault("PERSONA_CACHE", os.path.join(tempfile.mkdtemp(), "persona.json"))
os.environ.setdefault("EVENT_LOG", os.path.join(tempfile.mkdtemp(), "events.jsonl"))
os.environ.setdefault("LATENCY_LOG", os.path.join(tempfile.mkdtemp(), "latency.jsonl"))

from core import config                     # noqa: E402
from core import mitre                      # noqa: E402
from core.latency import (CLASS_PROFILE, GenerationBudget,  # noqa: E402
                          LatencyNormalizer, classify)
from core.llm import LLMResponse            # noqa: E402
from core.session import SessionStore       # noqa: E402
from roles.artifacts import ArtifactAgent   # noqa: E402
from roles.persona import PersonaAgent      # noqa: E402
from roles.terminal import TerminalAgent    # noqa: E402

PASSED = 0
FAILED: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    global PASSED
    if condition:
        PASSED += 1
        print(f"  PASS  {name}")
    else:
        FAILED.append(f"{name}{': ' + detail if detail else ''}")
        print(f"  FAIL  {name}  {detail}")


class StubLLM:
    """Stands in for Ollama. Always fails, forcing the fallback paths.

    Testing against the fallback is the stricter choice: it proves the decoy
    stays coherent even when inference is unavailable."""

    model = "stub"
    calls = 0

    def chat(self, *args, **kwargs) -> LLMResponse:
        StubLLM.calls += 1
        return LLMResponse("", 0.0, ok=False, error="stub: sin inferencia")

    def is_ready(self) -> bool:
        return False

    def has_model(self) -> bool:
        return False

    def warmup(self) -> LLMResponse:
        return LLMResponse("", 0.0, ok=False, error="stub")


def build():
    llm = StubLLM()
    persona = PersonaAgent(llm).load_or_generate(force=True)
    artifacts = ArtifactAgent(llm, persona)
    artifacts.build()
    terminal = TerminalAgent(llm, persona, artifacts)
    store = SessionStore()
    return persona, artifacts, terminal, store


def main() -> int:
    persona, artifacts, terminal, store = build()
    session = store.create("10.42.99.99", 54321)

    print("\n== Persona ==")
    check("hostname no vacio", bool(persona.hostname), persona.hostname)
    check("perfil de reserva al fallar el LLM", persona.generated_by == "fallback")
    check("/etc/passwd contiene root", "root:x:0:0:root:/root:/bin/bash" in persona.etc_passwd())
    check("usuarios de la persona presentes en /etc/passwd",
          all(u["name"] in persona.etc_passwd() for u in persona.users))
    check("uids unicos", len({u["uid"] for u in persona.users}) == len(persona.users))

    print("\n== Artefactos ==")
    check("filesystem virtual poblado", len(artifacts.fs.nodes) > 40,
          f"{len(artifacts.fs.nodes)} nodos")
    check("honeytokens registrados", len(artifacts.honeytokens) >= 4,
          f"{len(artifacts.honeytokens)}")
    check(".bash_history de root existe",
          artifacts.fs.get("/root/.bash_history") is not None)
    check(".bash_history no vacio",
          len((artifacts.fs.get("/root/.bash_history").content or "").strip()) > 50)
    check("log de nginx precargado", len(artifacts.access_log().split("\n")) > 100)

    print("\n== Coherencia determinista ==")
    r = terminal.resolve(session, "whoami")
    check("whoami == root", r.output == "root", repr(r.output))
    check("whoami es determinista", r.route == "deterministic")
    check("whoami por debajo de 1 ms", r.total_ms < 1.0, f"{r.total_ms:.3f} ms")

    r = terminal.resolve(session, "uname -a")
    check("uname -a cita el hostname de la persona", persona.hostname in r.output)

    passwd_1 = terminal.resolve(session, "cat /etc/passwd").output
    passwd_2 = terminal.resolve(session, "cat /etc/passwd").output
    check("cat /etc/passwd es identico entre invocaciones", passwd_1 == passwd_2)
    check("cat /etc/passwd coincide con la persona", passwd_1 == persona.etc_passwd())

    users_in_passwd = {ln.split(":")[0] for ln in passwd_1.split("\n")}
    home_dirs = {n.name for n in artifacts.fs.children("/home")}
    check("cada home corresponde a un usuario de /etc/passwd",
          home_dirs.issubset(users_in_passwd), f"{home_dirs - users_in_passwd}")

    print("\n== Navegacion y estado de sesion ==")
    terminal.resolve(session, "cd /var/www")
    check("cd actualiza el cwd", session.cwd == "/var/www", session.cwd)
    check("pwd refleja el cd", terminal.resolve(session, "pwd").output == "/var/www")
    terminal.resolve(session, "cd ..")
    check("cd .. sube un nivel", session.cwd == "/var", session.cwd)
    r = terminal.resolve(session, "cd /no/existe")
    check("cd a ruta inexistente da error de bash",
          "No such file or directory" in r.output, r.output)
    check("cwd intacto tras un cd fallido", session.cwd == "/var", session.cwd)

    terminal.resolve(session, "cd /tmp")
    terminal.resolve(session, "touch payload.sh")
    listing = terminal.resolve(session, "ls -la").output
    check("un fichero creado aparece luego en ls", "payload.sh" in listing, listing[:200])
    terminal.resolve(session, "rm payload.sh")
    listing = terminal.resolve(session, "ls -la").output
    check("un fichero borrado desaparece de ls", "payload.sh" not in listing)

    print("\n== Tuberias ==")
    r = terminal.resolve(session, "cat /etc/passwd | grep root")
    check("grep filtra la salida determinista",
          all("root" in ln for ln in r.output.split("\n") if ln), r.output[:120])
    check("la tuberia sigue siendo determinista", r.route == "deterministic")
    r = terminal.resolve(session, "cat /etc/passwd | wc -l")
    check("wc -l cuenta lineas", r.output.isdigit(), r.output)
    r = terminal.resolve(session, "ps aux | head -3")
    check("head -3 recorta a 3 lineas", len(r.output.split("\n")) == 3, r.output)

    print("\n== Honeytokens ==")
    env_node = artifacts.fs.get(f"/opt/{persona.app_name}/.env")
    check("el fichero .env existe", env_node is not None)
    matches = artifacts.match_honeytoken(env_node.content or "")
    check("los honeytokens se detectan en su propio fichero", len(matches) >= 3,
          f"{len(matches)}")
    check("no hay falsos positivos en texto benigno",
          artifacts.match_honeytoken("uid=0(root) gid=0(root)") == [])

    # El caso que importa: leer la clave privada debe disparar el honeytoken.
    key_node = artifacts.fs.get("/root/.ssh/id_rsa")
    check("la clave SSH privada existe", key_node is not None)
    check("leer la clave privada dispara su honeytoken",
          len(artifacts.match_honeytoken(key_node.content or "")) >= 1)
    check("cada honeytoken aparece de verdad en el fichero que dice ocuparlo",
          all(any(value in (n.content or "")
                  for n in artifacts.fs.nodes.values())
              for value in artifacts.honeytokens))

    print("\n== Clasificacion MITRE ATT&CK ==")
    check("whoami -> T1033", mitre.classify("whoami")["primary_technique"] == "T1033")
    check("uname -a -> T1082", mitre.classify("uname -a")["primary_technique"] == "T1082")
    check("ls -la -> T1083", mitre.classify("ls -la")["primary_technique"] == "T1083")
    ids = [t["technique_id"] for t in mitre.classify("cat /etc/passwd")["techniques"]]
    check("cat /etc/passwd -> T1087.001", "T1087.001" in ids, str(ids))
    check("cat /etc/passwd tiene severidad alta",
          mitre.classify("cat /etc/passwd")["severity"] >= 7)
    check("id_rsa se clasifica como acceso a credenciales",
          any(t["technique_id"] == "T1552.004"
              for t in mitre.classify("cat /root/.ssh/id_rsa")["techniques"]))
    check("un comando desconocido no rompe la clasificacion",
          mitre.classify("foobarbaz --xyz")["primary_technique"] == "T0000")

    print("\n== Degradacion sin inferencia ==")
    before = StubLLM.calls
    r = terminal.resolve(session, "figlet hola")
    check("un comando desconocido va a la ruta generativa", r.route == "generative")
    check("se intento la inferencia", StubLLM.calls > before)
    check("el fallo del LLM produce un error de shell creible",
          "command not found" in r.output, r.output)
    check("nunca se filtra el error interno al atacante",
          "stub" not in r.output.lower() and "error" not in r.output.lower(), r.output)

    print("\n== Higiene de salida ==")
    leaked = terminal._sanitise("As an AI language model, I cannot simulate that.", "ls")
    check("una respuesta que rompe el personaje se descarta",
          "command not found" in leaked, leaked)
    fenced = terminal._sanitise("```bash\nhello\n```", "echo hola")
    check("se eliminan los bloques de codigo markdown", fenced == "hello", repr(fenced))
    echoed = terminal._sanitise("root@srv:~# hello", "echo hola")
    check("se elimina el prompt reflejado", echoed == "hello", repr(echoed))

    print("\n== Binarios ausentes ==")
    r = terminal.resolve(session, "nmap -sV 10.42.18.0/24")
    check("nmap no existe en el senuelo", "command not found" in r.output, r.output)
    check("los binarios ausentes son deterministas", r.route == "deterministic")

    print("\n== Clasificacion por coste de comando ==")
    check("whoami es un builtin", classify("whoami") == "builtin", classify("whoami"))
    check("cat /etc/passwd es una lectura pequena",
          classify("cat /etc/passwd") == "read_small", classify("cat /etc/passwd"))
    check("ps aux recorre /proc", classify("ps aux") == "proc_scan", classify("ps aux"))
    check("find / es pesado", classify("find / -name x") == "heavy",
          classify("find / -name x"))
    check("un binario desconocido cae en unknown",
          classify("zzzfoo --bar") == "unknown", classify("zzzfoo --bar"))
    check("la clase la fija el primer segmento de la tuberia",
          classify("cat /etc/passwd | grep root") == "read_small")
    check("la recursion promueve a pesado",
          classify("ls -R /") == "heavy", classify("ls -R /"))
    # Regresion: el flag -r solo significa recursion en algunos binarios.
    # `uname -r` imprime la version del kernel y no cuesta nada.
    check("uname -r no se confunde con una recursion",
          classify("uname -r") == "read_small", classify("uname -r"))
    check("grep -r si es una recursion",
          classify("grep -r x /") == "heavy", classify("grep -r x /"))
    check("la ruta absoluta del binario no altera la clase",
          classify("/usr/bin/whoami") == "builtin")
    check("un comando vacio no rompe la clasificacion", classify("   ") == "builtin")

    print("\n== Normalizacion de latencia ==")
    norm = LatencyNormalizer(seed=1803)
    check("el RTT es constante dentro de una sesion",
          norm.session_rtt_ms("abc") == norm.session_rtt_ms("abc"))
    check("el RTT difiere entre sesiones",
          norm.session_rtt_ms("abc") != norm.session_rtt_ms("xyz"))
    # Cotas relativas a la configuracion, no absolutas: el RTT mediano es un
    # parametro de despliegue y un umbral fijo caducaria al cambiarlo.
    rtt = norm.session_rtt_ms("abc")
    check("el RTT es positivo y acotado por el techo del modelo",
          0 < rtt <= config.LATENCY_RTT_MEDIAN_MS * 8, f"{rtt:.1f} ms")

    # La propiedad central del modulo: el objetivo depende del comando, nunca
    # de la ruta que acabe respondiendo.
    a = LatencyNormalizer(seed=99)
    b = LatencyNormalizer(seed=99)
    check("misma semilla, misma secuencia de objetivos",
          [a.target_ms(c, "s1")[0] for c in ("ls", "ps", "find /")] ==
          [b.target_ms(c, "s1")[0] for c in ("ls", "ps", "find /")])

    n2 = LatencyNormalizer(seed=7)
    targets = [n2.target_ms("ls", "s1")[0] for _ in range(200)]
    check("un mismo comando no tarda siempre exactamente lo mismo",
          len(set(targets)) > 150, f"{len(set(targets))} distintos de 200")
    cap = CLASS_PROFILE["list_dir"][0] * 6.0 + n2.session_rtt_ms("s1") + 1
    check("la cola esta acotada", max(targets) <= cap, f"max {max(targets):.1f} ms")
    mean_target = sum(targets) / len(targets)
    floor = n2.session_rtt_ms("s1")
    check("todo objetivo incluye al menos el RTT de la sesion",
          min(targets) >= floor, f"min {min(targets):.1f} < rtt {floor:.1f}")
    check("el coste del comando se suma sobre el RTT",
          floor < mean_target < floor + CLASS_PROFILE["list_dir"][0] * 6,
          f"{mean_target:.1f} ms sobre un RTT de {floor:.1f} ms")
    check("un comando pesado apunta mas alto que un builtin",
          n2.target_ms("find / -name x", "s1")[0] > n2.target_ms("whoami", "s1")[0])

    print("\n== Relleno y desbordes ==")
    n3 = LatencyNormalizer(seed=5)
    res = n3.settle("whoami", "s1", elapsed_ms=0.5, route="deterministic")
    check("una respuesta rapida se rellena", res.slept_ms > 0)
    check("una respuesta rapida no cuenta como desborde", not res.overrun)
    res2 = n3.settle("zzz", "s1", elapsed_ms=9999.0, route="generative")
    check("una respuesta lenta se marca como desborde", res2.overrun)
    check("una respuesta lenta no se rellena", res2.slept_ms == 0.0)
    check("el desborde queda contabilizado", n3.stats.overruns == 1)
    check("el desborde se atribuye a su ruta",
          n3.stats.overruns_by_route.get("generative") == 1)
    check("la telemetria de normalizacion expone la clase",
          res.as_telemetry()["cmd_class"] == "builtin")

    print("\n== Cache de la ruta generativa ==")
    sess2 = store.create("10.42.99.98", 4242)
    calls_before = StubLLM.calls
    sess2.gen_cache[(sess2.cwd, "zzz")] = "salida cacheada"
    r = terminal.resolve(sess2, "zzz")
    check("un comando ya respondido sale de la cache",
          r.output == "salida cacheada", r.output)
    check("el acierto de cache se identifica", r.handler == "llm_cache", r.handler)
    check("el acierto de cache no llama al modelo", StubLLM.calls == calls_before,
          f"{StubLLM.calls} vs {calls_before}")
    sess2.add_file("/root/nuevo.txt", "x")
    check("una escritura invalida la cache", not sess2.gen_cache)

    # -- generation budget ------------------------------------------------
    # Padding cannot take time back, so the only defence against an overrun is
    # to have generated less. These check the arithmetic that decides how much
    # less, and that it degrades in the right order: tokens first, then the
    # prompt, and only then an honest admission that it does not fit.
    print("\n== Presupuesto de generacion ==")
    budget = GenerationBudget()

    generous = budget.plan("lsblk", 5000.0)
    check("un objetivo holgado no recorta por debajo del techo global",
          generous.max_tokens == config.MAX_TOKENS, str(generous.max_tokens))
    check("un objetivo holgado no necesita contexto reducido", not generous.lean)

    tight = budget.plan("lsblk", 750.0)
    check("el objetivo real de proc_scan recorta los tokens",
          tight.max_tokens < config.MAX_TOKENS,
          f"{tight.max_tokens} vs {config.MAX_TOKENS}")
    check("el recorte respeta el minimo de plausibilidad",
          tight.max_tokens >= config.GEN_MIN_TOKENS, str(tight.max_tokens))
    check("un objetivo mas holgado nunca concede menos tokens que uno estricto",
          budget.plan("lsblk", 2000.0).max_tokens >= tight.max_tokens)

    impossible = budget.plan("lsblk", 120.0)
    check("cuando no cabe con contexto completo se pasa al contexto reducido",
          impossible.lean)
    check("el contexto reducido replica menos turnos",
          impossible.context_turns < config.SESSION_CONTEXT_TURNS,
          str(impossible.context_turns))
    check("lo que no cabe se declara infactible en vez de ocultarse",
          not impossible.feasible)
    check("un plan infactible se responde igualmente, al minimo",
          impossible.max_tokens == config.GEN_MIN_TOKENS,
          str(impossible.max_tokens))
    check("la telemetria del plan expone el presupuesto aplicado",
          impossible.as_telemetry()["gen_max_tokens"] == impossible.max_tokens)

    # Calibration: a slower machine must produce a smaller budget for the same
    # target, because the estimate is fitted rather than assumed.
    before = budget.plan("lsblk", 750.0).max_tokens
    for _ in range(20):
        budget.observe(eval_tokens=64, eval_ms=64 * 45.0,
                       prompt_eval_ms=260.0, lean=False)
    after = budget.plan("lsblk", 750.0).max_tokens
    check("una maquina mas lenta recibe un presupuesto menor",
          after < before, f"{after} vs {before}")
    check("la calibracion queda registrada",
          budget.as_dict()["rate_samples"] == 20,
          str(budget.as_dict()["rate_samples"]))

    fast = GenerationBudget()
    for _ in range(20):
        fast.observe(eval_tokens=2, eval_ms=2 * 900.0,
                     prompt_eval_ms=240.0, lean=False)
    check("una respuesta de dos tokens no contamina el ritmo estimado",
          fast.as_dict()["rate_samples"] == 0,
          str(fast.as_dict()["rate_samples"]))

    # -- the target is drawn once ----------------------------------------
    # The budget is fitted to a target; padding to a *different* target would
    # silently reopen the timing channel this whole module exists to close.
    print("\n== El objetivo se sortea una sola vez ==")
    norm2 = LatencyNormalizer(seed=1803)
    drawn = norm2.target_ms("lsblk", "sesion-fija")
    settled = norm2.settle("lsblk", "sesion-fija", 10_000.0, route="generative",
                           drawn=drawn)
    check("el relleno usa el objetivo ya sorteado",
          abs(settled.target_ms - drawn[0]) < 1e-9,
          f"{settled.target_ms} vs {drawn[0]}")
    check("y su clase", settled.cls == drawn[1])

    # -- the paired suite is what it claims to be -------------------------
    # The reference run measured a suite whose comments were wrong: two
    # commands took the opposite route to the one declared, which left
    # read_small at 3/12 and proc_scan at 12/6 and quietly destroyed the
    # stratified comparison. Nothing about that needed Docker to detect --
    # the real routing decision is available right here -- so it is checked
    # here, where it fails in seconds instead of after a benchmark run.
    print("\n== Equilibrio de la suite emparejada ==")
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "benchmarks"))
    from latency_benchmark import (PAIRED_EXPECTED,  # noqa: E402
                                   PAIRED_SEQUENCE, assert_paired_balance)

    check("la declaracion de la suite esta equilibrada por clase",
          not assert_paired_balance(), "; ".join(assert_paired_balance()))
    check("cada comando emparejado esta declarado",
          {c for c, _, _ in PAIRED_SEQUENCE} == set(PAIRED_EXPECTED),
          str({c for c, _, _ in PAIRED_SEQUENCE} ^ set(PAIRED_EXPECTED)))

    observed: dict[str, dict[str, int]] = {}
    mismatches: list[str] = []
    for command, (exp_cls, exp_route) in PAIRED_EXPECTED.items():
        probe = store.create("10.42.99.97", 4243)
        route = terminal.resolve(probe, command).route
        cls = classify(command)
        if route != exp_route:
            mismatches.append(f"{command}: ruta {route} != {exp_route}")
        if cls != exp_cls:
            mismatches.append(f"{command}: clase {cls} != {exp_cls}")
        observed.setdefault(cls, {"deterministic": 0, "generative": 0})
        observed[cls][route] = observed[cls].get(route, 0) + 1

    check("cada comando toma la ruta y la clase que declara",
          not mismatches, "; ".join(mismatches))
    for cls in sorted(observed):
        counts = observed[cls]
        check(f"la clase '{cls}' queda equilibrada 3/3",
              counts["deterministic"] == counts["generative"] == 3,
              f"{counts['deterministic']} det / {counts['generative']} gen")
    print("\n" + "=" * 60)
    total = PASSED + len(FAILED)
    print(f"{PASSED}/{total} comprobaciones superadas")
    if FAILED:
        print("\nFallos:")
        for f in FAILED:
            print(f"  - {f}")
        return 1
    print("Todo correcto.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
