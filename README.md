# aya-lab

A collection of eBPF programs with [aya](https://aya-rs.dev/)

## (Optional) Set up environment on MacOS
- Install lima
```
brew install lima
```
- Edit cpu and memory configuration in `lima-vm/aya-lab.yaml`. Default values are:
```
cpus: 4
memory: "8GiB"
```
- Create a VM
```
limactl start lima-vm/aya-lab.yaml
```

## Blog posts

- [Writing eBPF Tracepoint Program with Rust Aya: Tips and Example](https://yuki-nakamura.com/2024/07/06/writing-ebpf-tracepoint-program-with-rust-aya-tips-and-example/)
- [Writing eBPF RawTracepoint Program with Rust Aya](https://yuki-nakamura.com/2024/08/12/writing-ebpf-rawtracepoint-program-with-rust-aya/)