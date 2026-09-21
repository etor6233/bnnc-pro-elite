/*
 * Adapted from aeron-samples (io.aeron:aeron), Apache-2.0, captured commit dad28d2 in external-review/low-latency-reference/aeron.
 *
 * This file adapts BasicPublisher.java, Copyright 2014-2025 Real Logic Limited,
 * licensed under the Apache License, Version 2.0 (https://www.apache.org/licenses/LICENSE-2.0).
 *
 * Changes versus the captured sample: fixed channel "aeron:ipc", stream id 1001,
 * a 32-byte payload whose first 8 bytes carry a little-endian System.nanoTime()
 * publish timestamp, a busy-spin offer loop, and progress output every 250,000 messages.
 */

import io.aeron.Aeron;
import io.aeron.Publication;
import org.agrona.BufferUtil;
import org.agrona.concurrent.BusySpinIdleStrategy;
import org.agrona.concurrent.UnsafeBuffer;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * One-way Aeron IPC latency publisher.
 * <p>
 * Publishes a fixed number of 32-byte messages (8-byte little-endian publish
 * timestamp plus 24 bytes of zero padding) on channel "aeron:ipc", stream id 1001.
 * The timestamp is refreshed immediately before each successful offer, so each
 * recorded latency is measured from just before the message is written.
 */
public class IpcLatencyPublisher
{
    private static final String CHANNEL = "aeron:ipc";
    private static final int STREAM_ID = 1001;
    private static final int PAYLOAD_SIZE = 32;
    private static final int TIMESTAMP_SIZE = 8;
    private static final long DEFAULT_MESSAGES = 1_000_000L;
    private static final long PROGRESS_INTERVAL = 250_000L;

    /**
     * Main method.
     *
     * @param args optional message count; defaults to 1,000,000.
     */
    public static void main(final String[] args)
    {
        final long messages = args.length > 0 ? Long.parseLong(args[0]) : DEFAULT_MESSAGES;

        System.out.println("Publishing " + messages + " messages to " + CHANNEL + " on stream id " + STREAM_ID);

        final Aeron.Context ctx = new Aeron.Context().idleStrategy(new BusySpinIdleStrategy());
        final BusySpinIdleStrategy offerIdle = new BusySpinIdleStrategy();

        final ByteBuffer byteBuffer = BufferUtil.allocateDirectAligned(PAYLOAD_SIZE, 64);
        byteBuffer.order(ByteOrder.LITTLE_ENDIAN);
        final UnsafeBuffer buffer = new UnsafeBuffer(byteBuffer);

        try (Aeron aeron = Aeron.connect(ctx);
            Publication publication = aeron.addPublication(CHANNEL, STREAM_ID))
        {
            long published = 0L;
            for (long i = 0L; i < messages; i++)
            {
                while (true)
                {
                    byteBuffer.putLong(0, System.nanoTime());
                    final long result = publication.offer(buffer, 0, PAYLOAD_SIZE);

                    if (result >= 0L)
                    {
                        published++;
                        break;
                    }

                    if (Publication.CLOSED == result || Publication.MAX_POSITION_EXCEEDED == result)
                    {
                        System.err.println("Offer failed permanently with result " + result);
                        return;
                    }

                    offerIdle.idle();
                }

                if (i > 0L && 0L == (i % PROGRESS_INTERVAL))
                {
                    System.out.println("Published " + i + " / " + messages);
                }
            }

            System.out.println("Done sending. Published " + published + " messages.");
        }
    }
}
