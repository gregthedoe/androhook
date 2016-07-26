Interceptor.attach(Module.findExportByName(null, "SSL_new"), {
    //SSL *SSL_new(SSL_CTX *ctx);
    onEnter: function(args) {
        this.sslCtxPointer = args[0]
    }
    , onLeave: function(retval) {
        var msg = {};
        msg["type"] = "function_call";
        msg["name"] = "SSL_new";
        msg["ssl_ctx_pointer"] = this.sslCtxPointer;
        msg["ssl_pointer"] = retval;
        send(msg);
    }
});

Interceptor.attach(Module.findExportByName(null, "SSL_write"), {
    // int (*ssl_write)(SSL *s,const void *buf,int len)
    onEnter: function(args) {
        this.sslNativePointer = args[0];
        this.buff = args[1];
        this.byteCount = args[2];
    }
    , onLeave: function(retval) {
        var msg = {};
        msg["type"] = "function_call";
        msg["name"] = "SSL_write";
        msg["ssl_pointer"] = this.sslNativePointer;
        if(retval.toInt32()<= 0) {
            var buff = ""
        }
        if(retval.toInt32() > 0) {
            var buff = Memory.readByteArray(ptr(this.buff.toInt32()), retval.toInt32());
        }
        send(msg, buff);
    }
});

Interceptor.attach(Module.findExportByName(null, "SSL_read"), {
    //int SSL_read(SSL *ssl, void *buf, int num);
    onEnter: function(args) {
        this.sslNativePointer = args[0];
        this.buff = args[1];
        this.byteCount = args[2];
    }
    , onLeave: function(retval) {
        var msg = {};
        msg["type"] = "function_call";
        msg["name"] = "SSL_read";
        msg["ssl_pointer"] = this.sslNativePointer;
        if(retval.toInt32()<= 0) {
            var buff = "";
        }
        if(retval.toInt32() > 0) {
            var buff = Memory.readByteArray(ptr(this.buff.toInt32()), retval.toInt32());
        }
        send(msg, buff);
    }
});

Interceptor.attach(Module.findExportByName(null, "SSL_free"), {
    //void SSL_free(SSL *ssl);
    onEnter: function(args) {
        this.sslNativePointer = args[0];
        var msg = {};
        msg["type"] = "function_call";
        msg["name"] = "SSL_free";
        msg["ssl_pointer"] = this.sslNativePointer;
        send(msg);
    }
});

Interceptor.attach(Module.findExportByName(null, "SSL_do_handshake"), {
    //int SSL_do_handshake(SSL *ssl);
    onEnter: function(args) {
        this.sslNativePointer = args[0]

    }
    , onLeave: function(retval) {
        var msg = {};
        msg["type"] = "function_call";
        msg["name"] = "SSL_do_handshake";
        msg["ssl_pointer"] = this.sslNativePointer;
        msg["retval"] = retval;
        send(msg);
    }
});

Interceptor.attach(Module.findExportByName(null, "SSL_shutdown"), {
    //int SSL_shutdown(SSL *ssl);
    onEnter: function(args) {
        this.sslNativePointer = args[0]
    }
    , onLeave: function(retval) {
        var msg = {};
        msg["type"] = "function_call";
        msg["name"] = "SSL_shutdown";
        msg["ssl_pointer"] = this.sslNativePointer;
        msg["retval"] = retval;
        send(msg);
    }
});

Interceptor.attach(Module.findExportByName(null, "SSL_set_fd"), {
    //int SSL_set_fd(SSL *ssl, int fd);
    onEnter: function(args) {
        this.sslNativePointer = args[0];
        this.fd = args[1];

    }
    , onLeave: function(retval) {
        var msg = {};
        msg["type"] = "function_call";
        msg["name"] = "SSL_set_fd";
        msg["ssl_pointer"] = this.sslNativePointer;
        msg["fd"] = this.fd;
        msg["retval"] = retval;
        if (retval.toInt32() == 1) {
            var localAddress = Socket.localAddress(this.fd);
            var peerAddress = Socket.peerAddress(this.fd);
        } else {
            var localAddress = {};
            var peerAddress = {};
        }
        msg["local_address"] = localAddress;
        msg["peer_address"] = peerAddress;
        send(msg);
    }
});

Interceptor.attach(Module.findExportByName(null, "SSL_renegotiate"), {
    //int SSL_renegotiate(SSL *ssl)
    onEnter: function(args) {
        this.sslNativePointer = args[0]
    }
    , onLeave: function(retval) {
        var msg = {};
        msg["type"] = "function_call";
        msg["name"] = "SSL_set_fd";
        msg["ssl_pointer"] = this.sslNativePointer;
        msg["retval"] = retval;
        send(msg);
    }
});