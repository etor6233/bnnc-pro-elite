/*
 * Adapted from aeron-samples (io.aeron:aeron), Apache-2.0, captured commit dad28d2 in external-review/low-latency-reference/aeron.
 *
 * This file adapts BasicSubscriber.java, Copyright 2014-2025 Real Logic Limited,
 * licensed under the Apache License, Version 2.0 (https://www.apache.org/licenses/LICENSE-2.0).
 *
 * Changes versus the captured sample: fixed channel "aeron:ipc", stream id 1001,
 * a fragment handler that reads the 8-byte little-endian publish timestamp and
 * records the one-way latency into an HdrHistogram, and results written to JSON.
 */

import io.aeron.Aeron;
import io.aeron.Subscription;
import io.aeron.logbuffer.FragmentHandler;
import org.HdrHistogram.Histogram;
import org.agrona.concurrent.BusySpinIdleStrategy;

import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * One-way Aeron IPC latency subscriber.
 * <p>
 * Subscribes to channel "aeron:ipc", stream id 1001, reads the 8-byte little-endian
 * publish timestamp from each 32-byte message and records
 * (System.nanoTime() - publishTimestamp) nanoseconds into an HdrHistogram
 * (lowestDiscernibleValue=1, highestTrackableValue=60,000,000,000 ns, 3 significant figures).
 * After a fixed number of messages the percentile summary and JSON results are written.
 */
public class IpcLatencySubscriber
{
    private static final String CHANNEL = "aeron:ipc";
    private static final int STREAM_ID = 1001;
    private static final long DEFAULT_MESSAGES = 1_000_000L;
    private static final long HIGHEST_TRACKABLE_VALUE_NS = 60_000_000_000L;
    private static final int SIGNIFICANT_FIGURES = 3;
    private static final String DEFAULT_OUTPUT_PATH = "aeron_ipc_results.json";

    /**
     * Main method.
     *
     * @param args optional message count and output path; defaults are 1,000,000 and aeron_ipc_results.json.
     */
    public static void main(final String[] args) throws Exception
    {
        final long messages = args.length > 0 ? Long.parseLong(args[0]) : DEFAULT_MESSAGES;
        final String outputPath = args.length > 1 ? args[1] : DEFAULT_OUTPUT_PATH;

        System.out.println("Subscribing to " + CHANNEL + " on stream id " + STREAM_ID);

        final Histogram histogram = new Histogram(1L, HIGHEST_TRACKABLE_VALUE_NS, SIGNIFICANT_FIGURES);
        final AtomicLong count = new AtomicLong(0L);
        final AtomicBoolean done = new AtomicBoolean(false);

        final Aeron.Context ctx = new Aeron.Context().idleStrategy(new BusySpinIdleStrategy());
        final BusySpinIdleStrategy pollIdle = new BusySpinIdleStrategy();

        final FragmentHandler fragmentHandler =
            (buffer, offset, length, header) ->
            {
                final long publishTimestamp = buffer.getLong(offset, ByteOrder.LITTLE_ENDIAN);
                histogram.recordValue(System.nanoTime() - publishTimestamp);
                if (count.incrementAndGet() >= messages)
                {
                    done.set(true);
                }
            };

        try (Aeron aeron = Aeron.connect(ctx);
            Subscription subscription = aeron.addSubscription(CHANNEL, STREAM_ID))
        {
            while (!done.get())
            {
                final int fragmentsRead = subscription.poll(fragmentHandler, 256);
                if (0 == fragmentsRead)
                {
                    pollIdle.idle();
                }
            }
        }

        final long total = histogram.getTotalCount();
        final long min = histogram.getMinValue();
        final long p50 = histogram.getValueAtPercentile(50.0);
        final long p90 = histogram.getValueAtPercentile(90.0);
        final long p99 = histogram.getValueAtPercentile(99.0);
        final long p999 = histogram.getValueAtPercentile(99.9);
        final long p9999 = histogram.getValueAtPercentile(99.99);
        final long max = histogram.getMaxValue();

        System.out.println("Received " + total + " messages.");
        System.out.println("min=" + min + " ns");
        System.out.println("p50=" + p50 + " ns");
        System.out.println("p90=" + p90 + " ns");
        System.out.println("p99=" + p99 + " ns");
        System.out.println("p99.9=" + p999 + " ns");
        System.out.println("p99.99=" + p9999 + " ns");
        System.out.println("max=" + max + " ns");
        histogram.outputPercentileDistribution(System.out, 1.0);

        final String json = buildResultsJson(total, min, p50, p90, p99, p999, p9999, max);
        Files.write(Paths.get(outputPath), json.getBytes(StandardCharsets.UTF_8));
        System.out.println("Results written to " + outputPath);
    }

    private static String buildResultsJson(
        final long count,
        final long min,
        final long p50,
        final long p90,
        final long p99,
        final long p999,
        final long p9999,
        final long max)
    {
        final StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"channel\": \"").append(CHANNEL).append("\",\n");
        sb.append("  \"streamId\": ").append(STREAM_ID).append(",\n");
        sb.append("  \"payloadSize\": 32,\n");
        sb.append("  \"unit\": \"ns\",\n");
        sb.append("  \"count\": ").append(count).append(",\n");
        sb.append("  \"min\": ").append(min).append(",\n");
        sb.append("  \"p50\": ").append(p50).append(",\n");
        sb.append("  \"p90\": ").append(p90).append(",\n");
        sb.append("  \"p99\": ").append(p99).append(",\n");
        sb.append("  \"p99.9\": ").append(p999).append(",\n");
        sb.append("  \"p99.99\": ").append(p9999).append(",\n");
        sb.append("  \"max\": ").append(max).append("\n");
        sb.append("}\n");
        return sb.toString();
    }
}
