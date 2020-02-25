# Build cita-cli docker image

## Build the arctifact

- First, install `musl-gcc`, default on `/usr/local/musl`

```bash
$ wget https://www.musl-libc.org/releases/musl-1.1.19.tar.gz
$ tar -xzvf musl-1.1.19.tar.gz
$ cd musl-1.1.19/
$ ./configure && make && sudo make install
$ sudo ln -sf /usr/local/musl/bin/musl-gcc /usr/local/bin/musl-gcc
```

- Second, add `x86_64-unknown-linux-musl` toolchain

```bash
$ rustup target add x86_64-unknown-linux-musl
```

- Third, build

```bash
$ cargo install --target x86_64-unknown-linux-musl --path .
```

## Build image

- First, copy the arctifact

```shell
cd release
cp ~/.cargo/bin/cita-cli  .
```

- Second, build images

```shell
docker image build -t cita-ce-cli .
```