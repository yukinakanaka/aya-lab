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
