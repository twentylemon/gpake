package gpake;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Timer to measure the elapsed time of one or many operations. The timer uses
 * {@link System#nanoTime()} to calculate the times. Timers should normally
 * be removed in production code; they are backed by {@link ArrayList}, which
 * can end up being slow if many times are added. This implementation is
 * not thread safe. Some basic use of the timer is as follows:
 *
 * <pre>
 * Timer timer = new Timer("fancy operation");
 * for (...){
 *     timer.start();
 *     fancyOperation();
 *     timer.stop();
 * }
 * System.out.println(timer);   //fancy operation: total, mean, stddev
 * </pre>
 *
 * @author Taras Mychaskiw
 */
public class Timer implements Comparable<Timer>, Serializable {

    /**
     * The start time of this timer.
     */
    private List<Long> startTimes;

    /**
     * The stop time of this timer.
     */
    private List<Long> stopTimes;

    /**
     * The total amount of time seen by this timer.
     */
    private long sum;

    /**
     * Name of this timer. Only used for {@link #toString()}.
     */
    private String label;

    /**
     * The default time unit to get/display the times in.
     */
    private TimeUnit defaultTimeUnit;

    /**
     * Constructs a new timer with a default label of "timer"  and the default
     * time unit as milliseconds.
     */
    public Timer(){
        this("timer");
    }

    /**
     * Constructs a new timer with the given label and the default time unit as milliseconds.
     * The label is only used in {@link #toString()}.
     *
     * @param label the label to give this timer
     */
    public Timer(String label){
        this(label, TimeUnit.NANOSECONDS);
    }

    /**
     * Constructs a new timer with default label of "timer" and the default time unit given.
     * The label is only used in {@link #toString()}.
     *
     * @param defaultTimeUnit the time unit this timer will output values in by default
     */
    public Timer(TimeUnit defaultTimeUnit){
        this("timer", 16, defaultTimeUnit);
    }

    /**
     * Constructs a new timer with the given label and the default time unit given.
     * The label is only used in {@link #toString()}.
     *
     * @param label the label to give this timer
     * @param defaultTimeUnit the time unit this timer will output values in by default
     */
    public Timer(String label, TimeUnit defaultTimeUnit){
        this(label, 16, defaultTimeUnit);
    }

    /**
     * Constructs a new timer with the given label. The label is only used in {@link #toString()}.
     *
     * @param label the label to give this timer
     * @param initialCapacity the initial size of the lists that hold the times
     * @param defaultTimeUnit the time unit this timer will output values in by default
     */
    public Timer(String label, int initialCapacity, TimeUnit defaultTimeUnit){
        startTimes = new ArrayList<>(initialCapacity);
        stopTimes = new ArrayList<>(initialCapacity);
        setLabel(label);
        setDefaultTimeUnit(defaultTimeUnit);
    }

    /**
     * Sets the timer label.
     *
     * @param label the new timer label
     */
    public void setLabel(String label){
        this.label = label;
    }

    /**
     * Returns the label for this timer.
     *
     * @return the timer label
     */
    public String getLabel(){
        return label;
    }

    /**
     * Sets the default time unit. The default time unit is used for all other
     * functions when no time unit is specified.
     *
     * @param defaultTimeUnit the time unit this timer will output values in by default
     */
    public void setDefaultTimeUnit(TimeUnit defaultTimeUnit){
        this.defaultTimeUnit = defaultTimeUnit;
    }

    /**
     * Returns the default time unit for this timer.
     *
     * @return the default time unit
     */
    public TimeUnit getDefaultTimeUnit(){
        return defaultTimeUnit;
    }

    /**
     * Sets a new start time to the current time.
     */
    public void start(){
        startTimes.add(0L);
        stopTimes.add(0L);
        startTimes.set(startTimes.size() - 1, System.nanoTime());
    }

    /**
     * Ends the most recently started timer.
     */
    public void stop(){
        long time = System.nanoTime();
        int idx = stopTimes.lastIndexOf(0L);
        stopTimes.set(idx, time);
        sum += getElapsedTime(idx);
    }

    /**
     * Aborts the current or previous timer.
     */
    public void abort(){
        if (stopTimes.get(stopTimes.size() - 1) != 0L){
            sum -= getElapsedTime(stopTimes.size() - 1);
        }
        startTimes.remove(startTimes.size() - 1);
        stopTimes.remove(stopTimes.size() - 1);
    }

    /**
     * Removes previous times until only `keep` remain.
     * @param keep
     */
    public void abort(int keep){
        while (startTimes.size() > keep){
            abort();
        }
    }

    /**
     * Returns the number of started timer clocks;
     *
     * @return the number of times taken
     */
    public int getNumTimes(){
        return startTimes.size();
    }

    /**
     * Returns the most recently stopped timer's elapsed time taken in nanoseconds.
     *
     * @return most recently stopped time in nanoseconds
     */
    private long getElapsedTime(){
        return getElapsedTime(getNumTimes() - 1);
    }

    /**
     * Returns the timer's elapsed time taken in nanoseconds.
     *
     * @return stopped time in nanoseconds
     */
    private long getElapsedTime(int idx){
        return stopTimes.get(idx) - startTimes.get(idx);
    }

    /**
     * Converts the time in nanoseconds to the time unit sent.
     *
     * @param time the time in nanoseconds
     * @param timeUnit the time unit to convert to
     * @return the time converted to the time unit specified
     */
    private long convert(long time, TimeUnit timeUnit){
        return timeUnit.convert(time, TimeUnit.NANOSECONDS);
    }

    /**
     * Returns the total time taken in the time unit specified.
     *
     * @param timeUnit the time unit to get the total elapsed time in
     * @return the total elapsed time in the unit specified
     */
    public long getTotalTime(TimeUnit timeUnit){
        return convert(sum, timeUnit);
    }

    /**
     * Returns the total time taken in the default time unit.
     *
     * @return the total elapsed time in default time unit
     */
    public long getTotalTime(){
        return getTotalTime(defaultTimeUnit);
    }

    /**
     * Returns the most recently stopped timer's time taken in the time unit specified.
     *
     * @param timeUnit the time unit to get the elapsed time in
     * @return the elapsed time in the unit specified
     */
    public long getTime(TimeUnit timeUnit){
        return convert(getElapsedTime(), timeUnit);
    }

    /**
     * Returns the most recently stopped timer's time taken in the default time unit.
     *
     * @return the elapsed time in the default time unit
     */
    public long getTime(){
        return getTime(defaultTimeUnit);
    }

    /**
     * Returns the average time taken by all of the recorded durations by this timer
     * in the time unit specified.
     *
     * @param timeUnit the time unit to get the total elapsed time in
     * @return the average time taken per operation
     */
    public long getMean(TimeUnit timeUnit){
        return convert(sum / (long)getNumTimes(), timeUnit);
    }

    /**
     * Returns the average time taken by all of the recorded durations by this
     * timer in the default time unit.
     *
     * @return the average time taken per operation
     */
    public long getMean(){
        return getMean(defaultTimeUnit);
    }

    /**
     * Returns the variance (standard deviation squared) of the times recorded
     * by this timer in the default time unit.
     *
     * @return variance of time per operation
     */
    public long getVariance(){
        return getVariance(defaultTimeUnit);
    }

    /**
     * Returns the variance (standard deviation squared) of the times recorded
     * by this timer in the time unit specified.
     *
     * @param timeUnit the time unit to get the total elapsed time in
     * @return variance of time per operation
     */
    public long getVariance(TimeUnit timeUnit){
        return getVariance(getMean(TimeUnit.NANOSECONDS), timeUnit);
    }

    /**
     * Returns the variance (standard deviation squared) of the times recorded
     * by this timer in the the default time unit.
     *
     * @param mean the mean time lapse recorded by this timer in nanoseconds
     * @return variance of time per operation
     */
    public long getVariance(long mean){
        return getVariance(mean, defaultTimeUnit);
    }

    /**
     * Returns the variance (standard deviation squared) of the times recorded
     * by this timer in the time unit specified.
     *
     * @param mean the mean time lapse recorded by this timer in nanoseconds
     * @param timeUnit the time unit to get the total elapsed time in
     * @return variance of time per operation
     */
    public long getVariance(long mean, TimeUnit timeUnit){
        long variance = 0;
        for (int i = 0; i < getNumTimes(); i++){
            long time = getElapsedTime(i);
            variance += (time - mean) * (time - mean);
        }
        return convert(variance / (long)getNumTimes(), timeUnit);
    }

    /**
     * Returns the comparative time between this timer and the other.
     *
     * @param timer the other time to compare to
     * @return negative, zero or positive if the time of this timer is less than,
     *  equal to or greater than (respectfully) the other timer
     */
    @Override
    public int compareTo(Timer timer){
        long diff = sum - timer.sum;
        if (diff < 0){
            return -1;
        }
        else if (diff > 0){
            return 1;
        }
        return 0;
    }

    /**
     * Returns true if the total times taken by the two timers is the same.
     *
     * @param obj a timer to compare to
     * @return true if the two timers stored the same total elapsed time
     */
    @Override
    public boolean equals(Object obj){
        return obj instanceof Timer && ((Timer)obj).sum == sum;
    }

    /**
     * Returns the hashcode for this timer based on the total time passed.
     *
     * @return the timer hashcode
     */
    @Override
    public int hashCode(){
        return 37 * 5 + (int) (this.sum ^ (this.sum >>> 32));
    }

    /**
     * Returns a string representation of this timer. Contains the label, total
     * time, mean time and standard deviation of the times all in the default time unit.
     *
     * @return a string representation of this timer
     */
    @Override
    public String toString(){
        long mean = getMean(TimeUnit.NANOSECONDS);
        long variance = getVariance(mean, TimeUnit.NANOSECONDS);
        String unit = Timer.getUnit(defaultTimeUnit);
        return String.format("%s: %d%s, mean: %d%s, stddev: %d%s", label,
                getTotalTime(defaultTimeUnit), unit,
                convert(mean, defaultTimeUnit), unit,
                convert((long)Math.sqrt(variance), defaultTimeUnit), unit);
    }

    /**
     * Returns the unit of the time unit. For example, <tt>"s"</tt> is returned for seconds.
     *
     * @param timeUnit the time unit to get the unit of
     * @return the unit of the time unit
     */
    public static String getUnit(TimeUnit timeUnit){
        switch (timeUnit){
            case DAYS: return "d";
            case HOURS: return "h";
            case MINUTES: return "m";
            case SECONDS: return "s";
            case MILLISECONDS: return "ms";
            case MICROSECONDS: return "us";
            case NANOSECONDS: return "ns";
        }
        return null;
    }
}
