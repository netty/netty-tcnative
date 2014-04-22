package org.apache.tomcat.jni.ssl;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * Manages a pool of directly-allocated ByteBuffers.
 *
 * This is necessary as the reclamation of these buffers does not work appropriately
 * on some platforms.
 *
 * TODO: Attempt to replace the directly-allocated ByteBuffers this with one APR pool.
 */
public class DirectBufferPool {
    private LinkedBlockingQueue<ByteBuffer> buffers;

    // BUFFER_SIZE must be large enough to accomodate the maximum SSL record size.
    // Header (5) + Data (2^14) + Compression (1024) + Encryption (1024) + MAC (20) + Padding (256)
    private final int BUFFER_SIZE = 18713;

    /**
     * Construct a new pool with the specified capacity.
     *
     * @param capacity The number of buffers to instantiate.
     */
    public DirectBufferPool(int capacity) {
        buffers = new LinkedBlockingQueue<ByteBuffer>(capacity);
        while (buffers.remainingCapacity() > 0) {
            ByteBuffer buf = ByteBuffer.allocateDirect(BUFFER_SIZE);

            buf.order(ByteOrder.nativeOrder());

            buffers.offer(buf);
        }
    }

    /**
     * Take a buffer from the pool.
     *
     * @returns a ByteBuffer.
     */
    public ByteBuffer acquire() throws InterruptedException {
        return buffers.take();
    }

    /**
     * Release a buffer back into the stream
     *
     * @param buffer the ByteBuffer to release
     */
    public void release(ByteBuffer buffer) {
        buffer.clear();
        buffers.offer(buffer);
    }

    @Override
    public String toString() {
        return "[DirectBufferPool " +
            buffers.size() + " buffers * " +
            BUFFER_SIZE + " bytes = " +
            buffers.size() * BUFFER_SIZE + " total bytes; " +
            "size: " + buffers.size() +
            " remainingCapacity: " + buffers.remainingCapacity() +
            "]";
    }
}
