package org.apache.tomcat.jni.ssl;

import org.apache.tomcat.jni.Buffer;

import java.nio.ByteBuffer;

abstract class DirectBufferOperation {
    private final static RuntimeException ALLOCATION_INTERRUPTED =
        new IllegalStateException("Buffer allocation interrupted");

    private DirectBufferPool pool;

    public DirectBufferOperation(DirectBufferPool pool) {
        this.pool = pool;

        ByteBuffer buffer = acquireDirectBuffer();
        try {
            run(buffer, Buffer.address(buffer));
        } finally {
            releaseDirectBuffer(buffer);
        }
    }

    private ByteBuffer acquireDirectBuffer() {
        try {
            return pool.acquire();
        } catch (InterruptedException e) {
            throw ALLOCATION_INTERRUPTED;
        }
    }

    private void releaseDirectBuffer(ByteBuffer buffer) {
        buffer.rewind();
        buffer.clear();
        pool.release(buffer);
    }

    abstract void run(ByteBuffer buffer, long address);
}
