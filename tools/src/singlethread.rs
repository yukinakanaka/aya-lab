use std::thread;
use std::time::{Duration, Instant};

fn main() {
    let tid_main = thread::current().id();
    println!("Main thread id = {:?}", tid_main);

    let start = Instant::now();

    for i in 0..10 {
        println!("Iteration {} of {:?} is starting to sleep", i, tid_main);
        thread::sleep(Duration::from_secs(1));
        println!("Iteration {} of {:?} has finished sleeping", i, tid_main);
    }

    let duration = start.elapsed();
    println!(
        "All iterations have finished in {:.3} seconds.",
        duration.as_secs_f64()
    );
}
