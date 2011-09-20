package org.agora.utils;

public class SimpleLock {
    protected boolean isLocked = false;

    public synchronized void lock() {
        try {
            unsafeLock();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    public synchronized void unsafeLock() throws InterruptedException {
        while (isLocked) {
            wait();
        }
        isLocked = true;
    }

    public synchronized void unlock() {
        isLocked = false;
        notify();
    }
}
