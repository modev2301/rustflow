use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn fibonacci_slow(n: u64) -> u64 {
    match n {
        0 => 1,
        1 => 1,
        n => fibonacci_slow(n - 1) + fibonacci_slow(n - 2),
    }
}

fn fibonacci_benchmark(c: &mut Criterion) {
    c.bench_function("fib 20", |b| b.iter(|| fibonacci_slow(black_box(20))));
}

criterion_group!(benches, fibonacci_benchmark);
criterion_main!(benches); 