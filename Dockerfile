FROM ubuntu:22.04 as streamline-base
ENV LC_ALL=C.UTF-8

# Install and update packages
RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y build-essential curl

# Add user
ENV STREAMLINE=/home/user/streamline
RUN useradd -l -u 1000 -d /home/user user && \
    mkdir -p $STREAMLINE /home/user/.cache && \
    chown -R user:user /home/user && \
    echo "user ALL=(ALL) NOPASSWD: ALL" >/etc/sudoers

# Install and update Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs >/tmp/rustup.sh && \
    chmod +x /tmp/rustup.sh && \
    /tmp/rustup.sh -y && \
    . $HOME/.cargo/env && \
    rustup update

# Create streamline container
FROM streamline-base as streamline
WORKDIR $STREAMLINE
COPY . $STREAMLINE
RUN . $HOME/.cargo/env && \
    cargo build --release
RUN ln -s $(pwd)/target/release/streamline /usr/local/bin/streamline

# Start in target dir as user
ENV TARGETS=/home/user/targets
USER user:user
WORKDIR $TARGETS
