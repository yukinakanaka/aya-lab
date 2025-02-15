use std::thread;
use std::time::{Duration, Instant};

fn main() {
    let mut handles = vec![];

    let tid_main = thread::current().id();
    println!("Main thread id = {:?}", tid_main);

    let start = Instant::now();

    for i in 0..10 {
        let handle = thread::spawn(move || {
            let tid = thread::current().id();
            println!("Thread {} (ID: {:?}) is sleeping", i, tid);

            thread::sleep(Duration::from_secs(1));
            println!("Thread {} (ID: {:?}) has woken up", i, tid);
        });
        handles.push(handle);
    }

    for handle in handles {
        // 各スレッドが終わるまで待機する
        handle.join().unwrap();
    }

    let duration = start.elapsed();
    println!(
        "All threads have finished in {:.3} seconds.",
        duration.as_secs_f64()
    );
}
