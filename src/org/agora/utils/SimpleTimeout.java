package org.agora.utils;

/**
 * Simple timeout class handler.
 *
 * This class allows you to detect when a blocking operation is too slow and
 * execute something after a given timeout. Example:
 *
 * <code>
 * SimpleTimeout timeout = new SimpleTimeout(5000) {
 *      public void timeout() {
 *          System.out.println("detected: operation is too slow! Aborting..");
 *          System.exit(-1);
 *      }
 *  };
 *  timeout.start();
 *  startSlowBlockingOperation();
 *  timeout.finish();
 * </code>
 */
abstract public class SimpleTimeout {
    protected Thread mThread = null;
    protected boolean mFinished = false;

    /**
     * Constructor. Creates a new SimpleTimeout object.
     *
     * @param timeoutMillisecs time after which the timeout() function should
     *        be triggered, in milliseconds.
     */
    public SimpleTimeout(int timeoutMillisecs) {
        final int millisecs = timeoutMillisecs;
        mThread = new Thread(new Runnable() {
            public void run()
            {
                try {
                    Thread.sleep(millisecs);

                    timeoutCheck();
                } catch (Exception e) {
                    // Should never happen
                    e.printStackTrace();
                }
            }
        });
    }

    protected synchronized void timeoutCheck() {
        if (!hasFinished()) {
            timeout();
        }
    }

    protected synchronized void setFinished(boolean finished) {
        mFinished = finished;
    }

    protected synchronized boolean hasFinished() {
        return mFinished;
    }

    /**
     * Function called when the operation timesout. Reimplement as needed.
     */
    abstract public void timeout();

    /**
     * Launches the timeout operation. Internally calls to start to the
     * thread controlling the timeout.
     */
    public void start() {
        mFinished = false;
        mThread.start();
    }

    /**
     * Stops the timeout operation. You should call to this function after
     * the blocking operation ends. Only if the time between the call to start()
     * and the call to this function is less than the timeout time specified
     * to the constructor, timeout() function will not be called.
     */
    public void finish() {
        setFinished(true);
    }

}