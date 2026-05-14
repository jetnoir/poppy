// Poppy V5 — Trust Boundary Agent
// Frida agent observing trust-boundary primitives in target daemon.
// Companion to xpc_observer.js (style match: emit() + JSONL via send()).
//
// Hooks:
//   - CFGetTypeID                    (SECD-01 / type-confusion class)
//   - CFDictionaryGetValue           (key-based dispatch lookups)
//   - CFArrayGetValueAtIndex         (index-bound check pattern)
//   - SecTaskCopyValueForEntitlement (entitlement gate — duplicates xpc_observer)
//   - SecTaskCopySigningIdentifier   (caller code-signing identity)
//   - xpc_dictionary_get_string      (XPC payload field reads)
//   - xpc_dictionary_get_value       (XPC payload field reads)
//
// Each emission has shape:
//   { ts, pid, kind, data, ret_ptr? }
//
// No rate-limiting — short observation windows only (~60s recommended).

'use strict';

function emit(kind, data, ret) {
    send({
        ts:   Date.now(),
        pid:  Process.id,
        kind: kind,
        data: data,
        ...(ret !== undefined ? {ret_ptr: ret.toString()} : {})
    });
}

function cfStrToUtf8(ptr) {
    if (ptr.isNull()) return null;
    try {
        const CFStringGetCStringPtr = new NativeFunction(
            Module.findExportByName('CoreFoundation','CFStringGetCStringPtr'),
            'pointer', ['pointer','uint32']);
        const cstr = CFStringGetCStringPtr(ptr, 0x08000100); // kCFStringEncodingUTF8
        if (!cstr.isNull()) return cstr.readUtf8String();
    } catch (e) {}
    return '<cfstr@' + ptr + '>';
}

function hookExport(mod, sym, prelude, ret_handler) {
    const addr = Module.findExportByName(mod, sym);
    if (!addr) { console.log('[poppy.tb] miss: ' + sym); return; }
    Interceptor.attach(addr, {
        onEnter: function(args) { try { prelude.call(this, args); } catch(e){} },
        onLeave: function(rv)   { try { if (ret_handler) ret_handler.call(this, rv); } catch(e){} }
    });
}

// ── CFGetTypeID — sample 1/100 to avoid storm
let cf_count = 0;
hookExport('CoreFoundation','CFGetTypeID', function(args){
    cf_count++;
    if (cf_count % 100 !== 0) return;
    this._sample = true;
    this._obj = args[0];
}, function(rv){
    if (this._sample) emit('cf.getTypeID', {obj: this._obj.toString(), sampled: true}, rv);
});

// ── CFDictionaryGetValue — key-based lookup
hookExport('CoreFoundation','CFDictionaryGetValue', function(args){
    this._key = cfStrToUtf8(args[1]);
}, function(rv){
    emit('cf.dictGet', {key: this._key, hit: !rv.isNull()}, rv);
});

// ── CFArrayGetValueAtIndex
hookExport('CoreFoundation','CFArrayGetValueAtIndex', function(args){
    this._idx = args[1].toInt32();
}, function(rv){
    emit('cf.arrayGet', {idx: this._idx}, rv);
});

// ── SecTaskCopyValueForEntitlement
hookExport('Security','SecTaskCopyValueForEntitlement', function(args){
    this._ent = cfStrToUtf8(args[1]);
}, function(rv){
    emit('sec.entitlement', {key: this._ent, granted: !rv.isNull()}, rv);
});

// ── SecTaskCopySigningIdentifier
hookExport('Security','SecTaskCopySigningIdentifier', function(args){
    /* arg0 = SecTaskRef */
}, function(rv){
    emit('sec.signid', {result_cfstr: rv.isNull() ? null : cfStrToUtf8(rv)}, rv);
});

// ── xpc_dictionary_get_string
hookExport('libxpc.dylib','xpc_dictionary_get_string', function(args){
    try { this._key = args[1].readUtf8String(); } catch(e){ this._key = '<unreadable>'; }
}, function(rv){
    let val = null;
    try { if (!rv.isNull()) val = rv.readUtf8String(); } catch(e){}
    emit('xpc.dictGetStr', {key: this._key, val: val});
});

// ── xpc_dictionary_get_value
hookExport('libxpc.dylib','xpc_dictionary_get_value', function(args){
    try { this._key = args[1].readUtf8String(); } catch(e){ this._key = '<unreadable>'; }
}, function(rv){
    emit('xpc.dictGetVal', {key: this._key, hit: !rv.isNull()}, rv);
});

emit('agent.start', {agent: 'trust_boundary'});
