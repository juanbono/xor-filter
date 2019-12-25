# xor filter

A faster and smaller alternative to bloom filters and cuckoo filters[0].

I ported it to Rust just as an excuse to learn about the algorithm, benchmarking and probabilistic data structures.

## Usage

This library provides the `Xor8` datatype.

It provides 2 functions:

* `new`: to initialize a new filter with the provided keys.
* `contains`: to perform membership checks

```rust
use xor_filter::Xor8;

fn main() {
    let keys = vec![1, 2, 3];
    let filter = Xor8::new(keys);

    assert!(filter.contains(1));
}
```

## Status

The code is an almost verbatim port of the [reference implementation made in Go](https://github.com/FastFilter/xorfilter/blob/master/xorfilter.go).

## References

[0] [Xor Filters: Faster and Smaller Than Bloom Filters](https://lemire.me/blog/2019/12/19/xor-filters-faster-and-smaller-than-bloom-filters/)
