// Poppy V5 — XPC Observer Agent
// Hooks into target daemon to observe XPC connection acceptance + handler dispatch.
// Emits JSONL via Frida's send() — one event per line for easy pipelining.
//
// Key hooks:
//   - NSXPCListener -shouldAcceptNewConnection:  (gate for entitled clients)
//   - NSXPCConnection -resume                    (after connection accepted)
//   - NSXPCConnection _callHandlerOnClientDisconnect: etc.
//   - xpc_connection_send_message_with_reply (client-side)
//   - SecTaskCopyValueForEntitlement         (entitlement lookup)
//
// Each emission has shape:
//   { ts, pid, kind, data, backtrace? }

'use strict';

const SENT = new Set();

function emit(kind, data, bt) {
    send({
        ts:   Date.now(),
        pid:  Process.id,
        kind: kind,
        data: data,
        ...(bt ? {bt: bt} : {})
    });
}

function asStr(x) {
    try {
        if (!x || x.isNull()) return null;
        const nsx = new ObjC.Object(x);
        return nsx.toString();
    } catch (_) { return null; }
}

function quickBT() {
    // Two frames is enough to identify the direct caller without blowing log volume
    return Thread.backtrace(this.context, Backtracer.ACCURATE)
        .slice(0, 4)
        .map(DebugSymbol.fromAddress)
        .map(s => s.toString());
}

// ── 1. NSXPCListener gate ─────────────────────────────────────────────────────
if (ObjC.available) {
    const NSXPCListener = ObjC.classes.NSXPCListener;
    if (NSXPCListener) {
        // shouldAcceptNewConnection: is the CRITICAL entitlement-check gate.
        // If it returns YES, the connection proceeds. Observing both sides tells us
        // exactly which clients pass the entitlement check.
        const selector = ObjC.selector('listener:shouldAcceptNewConnection:');

        // Hook is installed on ALL classes implementing this delegate method
        // via Interceptor.attach on -listener:shouldAcceptNewConnection: resolved
        ObjC.classes.NSObject['- listener:shouldAcceptNewConnection:'];
        // Instead: instrument every class that responds to this selector at first call
        for (const className in ObjC.classes) {
            const cls = ObjC.classes[className];
            try {
                const method = cls['- listener:shouldAcceptNewConnection:'];
                if (!method) continue;
                Interceptor.attach(method.implementation, {
                    onEnter: function(args) {
                        this.delegateClass = className;
                        this.listener      = new ObjC.Object(args[2]);
                        this.connection    = new ObjC.Object(args[3]);
                    },
                    onLeave: function(retval) {
                        let clientPid = null, auditToken = null, effectiveUID = null;
                        try { clientPid    = this.connection.processIdentifier(); } catch(_){}
                        try { effectiveUID = this.connection.effectiveUserIdentifier(); } catch(_){}
                        emit('xpc.shouldAcceptNewConnection', {
                            delegate:      this.delegateClass,
                            listener:      this.listener.toString(),
                            connection:    this.connection.toString(),
                            client_pid:    clientPid,
                            effective_uid: effectiveUID,
                            accepted:      retval.toInt32() !== 0,
                        });
                    }
                });
            } catch(_) {}
        }
        emit('poppy.bootstrap', {note: 'NSXPCListener hooks installed'}, null);
    }
}

// ── 2. SecTaskCopyValueForEntitlement ────────────────────────────────────────
// Traces entitlement checks against the client's task. This is how NSXPCListener
// typically validates callers. Logging this tells us exactly which entitlement
// string gated which connection.
try {
    const secTaskFn = Module.findGlobalExportByName('SecTaskCopyValueForEntitlement');
    if (secTaskFn) {
        Interceptor.attach(secTaskFn, {
            onEnter: function(args) {
                this.entKey = asStr(args[1]);
            },
            onLeave: function(retval) {
                emit('sec.entitlement.check', {
                    key:   this.entKey,
                    value: asStr(retval),
                });
            }
        });
    }
} catch(e) { emit('poppy.error', {hook:'SecTask', err: e.toString()}); }

// ── 3. xpc_connection_send_message_with_reply ────────────────────────────────
// When the daemon sends a reply to the client, capture the dictionary keys.
// This tells us the shape of the reply without logging full contents.
try {
    const sendFn = Module.findGlobalExportByName('xpc_connection_send_message_with_reply');
    if (sendFn) {
        Interceptor.attach(sendFn, {
            onEnter: function(args) {
                emit('xpc.send_reply', {dict: asStr(args[1])});
            }
        });
    }
} catch(_){}

// ── 4. CFGetTypeID + CFDictionaryGetValue (trust-boundary probe, SECD-01 style) ─
// Logs type inspections of dictionary values — catches the pattern where a
// daemon reads an attacker-controlled attribute and assumes a specific CF type.
try {
    const cfGet = Module.findGlobalExportByName('CFGetTypeID');
    if (cfGet) {
        Interceptor.attach(cfGet, {
            onEnter: function(args) { this.obj = args[0]; },
            onLeave: function(retval) {
                // High volume — only sample 1/1000 to avoid drowning output.
                if (Math.random() < 0.001) {
                    emit('cf.getTypeID', {
                        obj:    this.obj ? this.obj.toString() : null,
                        typeID: retval.toInt32(),
                    });
                }
            }
        });
    }
} catch(_){}

// ── 5. Swift fatalError / assertionFailure hook (IntelPCore-style) ─────────────
// Catch Swift assertion fires BEFORE the trap. These produce the fatalError
// string message as the first argument.
try {
    ['$ss17_assertionFailure__4file4line5flagss5NeverOs12StaticStringV_SSAHSuADtF',
     '$ss16_assertionFailure__4file4line5flagss5NeverOs12StaticStringV_A2GSuADtF',
     '_swift_stdlib_reportFatalError',
     '_swift_stdlib_reportFatalErrorInFile'].forEach(sym => {
        const addr = Module.findGlobalExportByName(sym);
        if (addr) {
            Interceptor.attach(addr, {
                onEnter: function(args) {
                    emit('swift.fatalError', {
                        symbol: sym,
                        // Swift StaticString first field is a pointer to UTF-8
                        prefix: Memory.readUtf8String(args[0].readPointer(), 256),
                        message: Memory.readUtf8String(args[2].readPointer(), 256),
                    }, quickBT.call(this));
                }
            });
        }
    });
} catch(e) { emit('poppy.error', {hook:'swift.fatalError', err: e.toString()}); }

emit('poppy.ready', {ts: Date.now(), target: Process.id});
