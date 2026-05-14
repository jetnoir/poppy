// Poppy V5 — xpc_malform.m
// ObjC-based fault injector — avoids ctypes-to-XPC segfault on arm64.
// Usage: xpc_malform <service> <variant>
//   variant: empty|size|nest|type
// Prints one JSON line with result; exits 0 on completion (even on XPC error).
#import <Foundation/Foundation.h>
#import <xpc/xpc.h>

static xpc_object_t build_empty(void) {
    return xpc_dictionary_create(NULL, NULL, 0);
}

static xpc_object_t build_size(void) {
    xpc_object_t m = xpc_dictionary_create(NULL, NULL, 0);
    size_t sz = 1 << 20;
    uint8_t *buf = calloc(1, sz);
    if (buf) { xpc_dictionary_set_data(m, "payload", buf, sz); free(buf); }
    return m;
}

static xpc_object_t build_nest(void) {
    xpc_object_t inner = xpc_dictionary_create(NULL, NULL, 0);
    for (int i = 0; i < 200; i++) {
        xpc_object_t outer = xpc_dictionary_create(NULL, NULL, 0);
        xpc_dictionary_set_value(outer, "n", inner);
        inner = outer;
    }
    xpc_object_t m = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_value(m, "nest", inner);
    return m;
}

static xpc_object_t build_type(void) {
    xpc_object_t m = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_string(m, "sel", "bogus:type:");
    xpc_dictionary_set_int64(m, "flags", 0xdeadbeefcafebabeULL);
    xpc_object_t arr = xpc_array_create(NULL, 0);
    for (int i = 0; i < 64; i++) {
        xpc_array_set_int64(arr, XPC_ARRAY_APPEND, 0x4141414141414141ULL);
    }
    xpc_dictionary_set_value(m, "args", arr);
    return m;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <service> <variant>\n", argv[0]);
        return 2;
    }
    const char *svc     = argv[1];
    const char *variant = argv[2];

    xpc_object_t msg = NULL;
    if      (!strcmp(variant, "empty")) msg = build_empty();
    else if (!strcmp(variant, "size"))  msg = build_size();
    else if (!strcmp(variant, "nest"))  msg = build_nest();
    else if (!strcmp(variant, "type"))  msg = build_type();
    else { fprintf(stderr, "unknown variant %s\n", variant); return 2; }

    dispatch_queue_t q = dispatch_queue_create("poppy.inject", DISPATCH_QUEUE_SERIAL);
    xpc_connection_t conn = xpc_connection_create_mach_service(svc, q, 0);
    if (!conn) {
        printf("{\"service\":\"%s\",\"variant\":\"%s\",\"result\":\"connect_fail\"}\n",
               svc, variant);
        return 1;
    }
    // Null-ish event handler required to resume a connection safely
    xpc_connection_set_event_handler(conn, ^(xpc_object_t ev) { (void)ev; });
    xpc_connection_resume(conn);

    xpc_object_t reply = xpc_connection_send_message_with_reply_sync(conn, msg);
    xpc_type_t rtype = xpc_get_type(reply);
    const char *kind = "unknown";
    const char *desc = "";
    if (rtype == XPC_TYPE_ERROR) {
        kind = "error";
        if (reply == XPC_ERROR_CONNECTION_INTERRUPTED) desc = "interrupted";
        else if (reply == XPC_ERROR_CONNECTION_INVALID) desc = "invalid";
        else if (reply == XPC_ERROR_TERMINATION_IMMINENT) desc = "termination";
        else desc = "unknown_error";
    } else if (rtype == XPC_TYPE_DICTIONARY) {
        kind = "reply_dict";
    } else {
        kind = "other_type";
    }
    printf("{\"service\":\"%s\",\"variant\":\"%s\",\"result\":\"%s\",\"desc\":\"%s\"}\n",
           svc, variant, kind, desc);
    fflush(stdout);

    xpc_connection_cancel(conn);
    return 0;
}
