# agent-filter: proxy environment for the agent account only.
# Staged at /usr/local/share/agent-filter/agent-proxy.sh by install.sh.
# The setup guide activates it (section 17.4) by installing it into
# /etc/profile.d/ — install.sh itself must never do that.
#
# Well-behaved tools honour these variables; the per-account firewall rules
# are what catches anything that ignores them. NO_PROXY keeps the agent's
# own loopback apps direct.
if [ "$(id -un)" = "agent" ]; then
  export HTTP_PROXY=http://127.0.0.1:8888
  export HTTPS_PROXY=http://127.0.0.1:8888
  export NO_PROXY=localhost,127.0.0.1
fi
