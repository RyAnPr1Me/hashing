use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use chronohash::{ChronoHash, Mode};

fn bench_fast_mode(c: &mut Criterion) {
    let mut group = c.benchmark_group("fast_mode");
    
    let hasher = ChronoHash::new(Mode::Fast);
    
    // 10 bytes
    group.throughput(Throughput::Bytes(10));
    group.bench_function("10_bytes", |b| {
        let data = b"0123456789";
        b.iter(|| hasher.hash(black_box(data)));
    });
    
    // 100 bytes
    group.throughput(Throughput::Bytes(100));
    group.bench_function("100_bytes", |b| {
        let data = vec![b'x'; 100];
        b.iter(|| hasher.hash(black_box(&data)));
    });
    
    // 1 KB
    group.throughput(Throughput::Bytes(1024));
    group.bench_function("1kb", |b| {
        let data = vec![b'x'; 1024];
        b.iter(|| hasher.hash(black_box(&data)));
    });
    
    // 10 KB
    group.throughput(Throughput::Bytes(10240));
    group.bench_function("10kb", |b| {
        let data = vec![b'x'; 10240];
        b.iter(|| hasher.hash(black_box(&data)));
    });
    
    group.finish();
}

fn bench_normal_mode(c: &mut Criterion) {
    let mut group = c.benchmark_group("normal_mode");
    
    let hasher = ChronoHash::new(Mode::Normal);
    
    // 10 bytes
    group.throughput(Throughput::Bytes(10));
    group.bench_function("10_bytes", |b| {
        let data = b"0123456789";
        b.iter(|| hasher.hash(black_box(data)));
    });
    
    // 100 bytes
    group.throughput(Throughput::Bytes(100));
    group.bench_function("100_bytes", |b| {
        let data = vec![b'x'; 100];
        b.iter(|| hasher.hash(black_box(&data)));
    });
    
    // 1 KB
    group.throughput(Throughput::Bytes(1024));
    group.bench_function("1kb", |b| {
        let data = vec![b'x'; 1024];
        b.iter(|| hasher.hash(black_box(&data)));
    });
    
    group.finish();
}

criterion_group!(benches, bench_fast_mode, bench_normal_mode);
criterion_main!(benches);
