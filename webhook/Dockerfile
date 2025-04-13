# https://github.com/almir/docker-webhook
FROM almir/webhook:2.8.0

# Key from `ssh-keyscan github.com`
RUN mkdir -p /root/.ssh/ && echo \
  "github.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCj7ndNxQowgcQnjshcLrqPEiiphnt+VTTvDP6mHBL9j1aNUkY4Ue1gvwnGLVlOhGeYrnZaMgRK6+PKCUXaDbC7qtbW8gIkhL7aGCsOr/C56SJMy/BCZfxd1nWzAOxSDPgVsmerOBYfNqltV9/hWCqBywINIR+5dIg6JTJ72pcEpEjcYgXkE2YEFXV1JHnsKgbLWNlhScqb2UmyRkQyytRLtL+38TGxkxCflmO+5Z8CSSNY7GidjMIZ7Q4zMjA2n1nGrlTDkzwDCsw+wqFPGQA179cnfGWOWRVruj16z6XyvxvjJwbz0wQZ75XK5tKSb7FNyeIEs4TT4jk+S4dhPeAUC5y+bDYirYgM4GC7uEnztnZyaVWQ7B381AK4Qdrwt51ZqExKbQpTUNn+EjqoTwvqNj4kqx5QUCI0ThS/YkOxJCXmPUWZbhjpCg56i+2aB6CmK2JGhn57K5mj0MNdBXA4/WnwH6XoPWJzK5Nyu2zB3nAZp+S5hpQs+p1vN1/wsjk=" \
  > /root/.ssh/known_hosts

# NOTE: Beware of the file path used for hooks.json. Becuase almir/webhook installs
# a VOLUME to /etc/webhook, we cannot run our sed command as it modifies the volume
# and those changes are discarded:
# https://docs.docker.com/engine/reference/builder/#notes-about-specifying-volumes
COPY hooks.json /hooks.json
ARG WEBHOOK_SECRET
RUN sed -i "s|\$WEBHOOK_SECRET|$WEBHOOK_SECRET|g" /hooks.json
CMD ["-verbose", "-hooks=/hooks.json"]

ARG DOCKER_REGISTRY=ghcr.io
ARG DOCKER_USERNAME=gridlocknetwork
ARG DOCKER_PASSWORD
ENV DOCKER_REGISTRY=$DOCKER_REGISTRY DOCKER_USERNAME=$DOCKER_USERNAME DOCKER_PASSWORD=$DOCKER_PASSWORD
RUN apk add git openssh-client docker docker-compose
COPY redeploy.sh /redeploy.sh