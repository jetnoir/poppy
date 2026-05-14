// Poppy V5 — ObjC Probe Agent
// Selective objc_msgSend probe filtered by class allow-list.
// Style match: xpc_observer.js / trust_boundary.js — JSONL via send().
//
// Default behavior: NO probing (would be a perf storm). Set env var
// POPPY_OBJC_CLASSES to a comma-separated allow-list before launching:
//   POPPY_OBJC_CLASSES="FSClient,fskitdXPCServer" frida -l objc_probe.js …
//
// Each emission has shape:
//   { ts, pid, kind, data: { cls, sel, arg0?, arg1? } }

'use strict';

function emit(kind, data) {
    send({ ts: Date.now(), pid: Process.id, kind: kind, data: data });
}

function envCSV(name) {
    try {
        const getenv = new NativeFunction(
            Module.findExportByName(null,'getenv'),'pointer',['pointer']);
        const buf = Memory.allocUtf8String(name);
        const v = getenv(buf);
        if (v.isNull()) return [];
        return v.readUtf8String().split(',').map(s=>s.trim()).filter(Boolean);
    } catch(e) { return []; }
}

const ALLOW = new Set(envCSV('POPPY_OBJC_CLASSES'));
if (ALLOW.size === 0) {
    emit('agent.skip', {reason: 'POPPY_OBJC_CLASSES env var unset; no probe attached'});
} else {
    emit('agent.start', {agent: 'objc_probe', classes: [...ALLOW]});

    const msgSend = Module.findExportByName(null,'objc_msgSend');
    const objClassName = new NativeFunction(
        Module.findExportByName(null,'object_getClassName'),
        'pointer',['pointer']);
    const selName = new NativeFunction(
        Module.findExportByName(null,'sel_getName'),
        'pointer',['pointer']);

    function safeStr(p) {
        try { return p.isNull() ? null : p.readUtf8String(); } catch(e){ return null; }
    }
    function describeObj(p) {
        if (p.isNull()) return null;
        // Best-effort: classname + addr
        try {
            const cn = safeStr(objClassName(p));
            return { cls: cn, addr: p.toString() };
        } catch(e) { return { addr: p.toString() }; }
    }

    Interceptor.attach(msgSend, {
        onEnter: function(args) {
            try {
                const recv = args[0];
                if (recv.isNull()) return;
                const cls = safeStr(objClassName(recv));
                if (!cls || !ALLOW.has(cls)) return;
                const sel = safeStr(selName(args[1]));
                emit('objc.send', {
                    cls: cls,
                    sel: sel,
                    arg0: describeObj(args[2]),
                    arg1: describeObj(args[3])
                });
            } catch(e){}
        }
    });
}
