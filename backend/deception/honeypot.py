"""
IMMUNIS ACIN — RL-Adaptive Honeypot Engine

WHY: A static honeypot is a one-time trick. Once an attacker
recognises it, they avoid it forever. An RL-adaptive honeypot
EVOLVES — it learns which deception strategies maximise attacker
dwell time and minimise detection probability, then adapts in
real time.

The longer an attacker interacts with the honeypot, the more
intelligence we gather: their tools, techniques, procedures,
and objectives. This feeds directly into the Threat Actor
Fingerprinting (TAF) engine.

Reinforcement Learning formulation:
  State: s = (attacker_actions, honeypot_config, dwell_time, suspicion_level)
  Action: a = (response_type, delay, content_richness, error_realism)
  Reward: r = dwell_time_delta - detection_penalty

  Policy: π(a|s) = softmax(Q(s,a) / τ)
  Update: Q(s,a) ← Q(s,a) + α[r + γ·max_a' Q(s',a') - Q(s,a)]

  The honeypot learns to:
  - Respond slowly enough to seem real, fast enough to keep interest
  - Provide enough data to seem valuable, not enough to be useful
  - Introduce realistic errors that don't trigger attacker suspicion
  - Escalate engagement gradually to maximise intelligence capture

Honeypot types:
1. SSH honeypot — fake shell with realistic filesystem
2. HTTP honeypot — fake web application with login forms
3. Database honeypot — fake database with canary data
4. API honeypot — fake API endpoints with realistic responses
5. Email honeypot — fake mail server that captures credentials
6. File share honeypot — fake SMB/NFS with decoy documents
"""

import logging
import time
import math
import random
import hashlib
from typing import Optional
from datetime import datetime, timezone
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict

import numpy as np

logger = logging.getLogger("immunis.deception.honeypot")


class HoneypotType(str, Enum):
    """Types of honeypot services."""
    SSH = "ssh"
    HTTP = "http"
    DATABASE = "database"
    API = "api"
    EMAIL = "email"
    FILE_SHARE = "file_share"


class ResponseAction(str, Enum):
    """Actions the honeypot can take in response to attacker input."""
    ACCEPT = "accept"  # Accept the input, provide response
    DELAY = "delay"  # Accept but add artificial delay
    PARTIAL = "partial"  # Provide partial/incomplete response
    ERROR = "error"  # Return realistic error
    REDIRECT = "redirect"  # Redirect to deeper honeypot
    ESCALATE = "escalate"  # Escalate to more interactive honeypot
    DISCONNECT = "disconnect"  # Terminate connection (if blown)


@dataclass
class HoneypotState:
    """Current state of a honeypot interaction."""
    session_id: str
    honeypot_type: HoneypotType
    attacker_ip: str
    started_at: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)
    dwell_time_s: float = 0.0
    actions_taken: int = 0
    commands_received: list[str] = field(default_factory=list)
    responses_sent: list[str] = field(default_factory=list)
    suspicion_level: float = 0.0  # 0=unsuspecting, 1=knows it's a honeypot
    intelligence_gathered: list[dict] = field(default_factory=list)
    current_depth: int = 0  # How deep into the honeypot
    is_active: bool = True


@dataclass
class HoneypotConfig:
    """Configuration for a honeypot instance."""
    honeypot_id: str
    honeypot_type: HoneypotType
    port: int
    hostname: str = "prod-server-03"
    os_fingerprint: str = "Ubuntu 22.04 LTS"
    service_banner: str = ""
    response_delay_ms: tuple = (50, 200)  # min, max delay
    content_richness: float = 0.7  # 0=empty, 1=full fake data
    error_rate: float = 0.05  # Probability of realistic errors
    max_depth: int = 5  # Maximum interaction depth
    max_dwell_time_s: float = 3600  # 1 hour max
    enabled: bool = True


@dataclass
class InteractionRecord:
    """Record of a complete honeypot interaction."""
    session_id: str
    honeypot_type: HoneypotType
    attacker_ip: str
    started_at: str
    ended_at: str
    dwell_time_s: float
    actions_taken: int
    commands: list[str]
    intelligence: list[dict]
    max_depth_reached: int
    suspicion_at_end: float
    total_reward: float


class QLearningAgent:
    """
    Q-learning agent for honeypot response optimisation.

    Learns optimal response strategy to maximise attacker
    dwell time while minimising detection probability.

    State features:
    - Dwell time bucket (0-10s, 10-60s, 1-5min, 5-30min, 30min+)
    - Action count bucket (1-5, 6-20, 21-50, 50+)
    - Suspicion level bucket (low, medium, high)
    - Interaction depth (0-5)

    Actions:
    - ACCEPT, DELAY, PARTIAL, ERROR, REDIRECT, ESCALATE, DISCONNECT
    """

    def __init__(
        self,
        learning_rate: float = 0.1,
        discount_factor: float = 0.95,
        exploration_rate: float = 0.2,
        exploration_decay: float = 0.995,
        min_exploration: float = 0.05,
    ):
        self._lr = learning_rate
        self._gamma = discount_factor
        self._epsilon = exploration_rate
        self._epsilon_decay = exploration_decay
        self._min_epsilon = min_exploration

        # Q-table: state_key → {action → value}
        self._q_table: dict[str, dict[str, float]] = defaultdict(
            lambda: {a.value: 0.0 for a in ResponseAction}
        )

        self._total_updates: int = 0

    def _discretise_state(self, state: HoneypotState) -> str:
        """Convert continuous state to discrete state key."""
        # Dwell time bucket
        dwell = state.dwell_time_s
        if dwell < 10:
            dwell_bucket = "0-10s"
        elif dwell < 60:
            dwell_bucket = "10-60s"
        elif dwell < 300:
            dwell_bucket = "1-5min"
        elif dwell < 1800:
            dwell_bucket = "5-30min"
        else:
            dwell_bucket = "30min+"

        # Action count bucket
        actions = state.actions_taken
        if actions <= 5:
            action_bucket = "1-5"
        elif actions <= 20:
            action_bucket = "6-20"
        elif actions <= 50:
            action_bucket = "21-50"
        else:
            action_bucket = "50+"

        # Suspicion bucket
        if state.suspicion_level < 0.3:
            suspicion_bucket = "low"
        elif state.suspicion_level < 0.7:
            suspicion_bucket = "medium"
        else:
            suspicion_bucket = "high"

        # Depth
        depth = min(state.current_depth, 5)

        return f"{dwell_bucket}|{action_bucket}|{suspicion_bucket}|{depth}"

    def select_action(self, state: HoneypotState) -> ResponseAction:
        """Select action using epsilon-greedy policy."""
        state_key = self._discretise_state(state)

        # Exploration
        if random.random() < self._epsilon:
            # Don't disconnect during exploration unless suspicion is high
            if state.suspicion_level < 0.8:
                actions = [a for a in ResponseAction if a != ResponseAction.DISCONNECT]
            else:
                actions = list(ResponseAction)
            return random.choice(actions)

        # Exploitation
        q_values = self._q_table[state_key]
        best_action = max(q_values, key=q_values.get)
        return ResponseAction(best_action)

    def update(
        self,
        state: HoneypotState,
        action: ResponseAction,
        reward: float,
        next_state: HoneypotState,
    ) -> None:
        """Update Q-value using temporal difference learning."""
        state_key = self._discretise_state(state)
        next_state_key = self._discretise_state(next_state)

        current_q = self._q_table[state_key][action.value]
        next_max_q = max(self._q_table[next_state_key].values())

        # Q-learning update
        new_q = current_q + self._lr * (
            reward + self._gamma * next_max_q - current_q
        )
        self._q_table[state_key][action.value] = new_q

        # Decay exploration
        self._epsilon = max(
            self._min_epsilon,
            self._epsilon * self._epsilon_decay,
        )

        self._total_updates += 1

    def compute_reward(
        self,
        state: HoneypotState,
        action: ResponseAction,
        dwell_delta: float,
        intelligence_gained: bool,
    ) -> float:
        """
        Compute reward for a honeypot action.

        Reward = dwell_time_gain - detection_penalty + intelligence_bonus

        We want to maximise dwell time and intelligence gathering
        while minimising the chance the attacker realises it's a honeypot.
        """
        reward = 0.0

        # Dwell time reward (logarithmic — diminishing returns)
        if dwell_delta > 0:
            reward += math.log1p(dwell_delta) * 2.0

        # Intelligence bonus
        if intelligence_gained:
            reward += 5.0

        # Suspicion penalty (exponential — very bad if high)
        if state.suspicion_level > 0.5:
            reward -= (state.suspicion_level ** 2) * 10.0

        # Disconnect penalty (we want to keep them engaged)
        if action == ResponseAction.DISCONNECT:
            reward -= 3.0

        # Depth bonus (deeper = more intelligence)
        reward += state.current_depth * 0.5

        return reward

    def get_stats(self) -> dict:
        return {
            "q_table_size": len(self._q_table),
            "total_updates": self._total_updates,
            "exploration_rate": round(self._epsilon, 4),
            "learning_rate": self._lr,
            "discount_factor": self._gamma,
        }


class AdaptiveHoneypot:
    """
    RL-adaptive honeypot engine.

    Manages multiple honeypot instances, each with an RL agent
    that learns optimal deception strategies from attacker
    interactions.

    Usage:
        honeypot = AdaptiveHoneypot()

        # Configure honeypots
        honeypot.add_honeypot(HoneypotConfig(
            honeypot_id="ssh-01",
            honeypot_type=HoneypotType.SSH,
            port=2222,
        ))

        # Handle attacker interaction
        session = honeypot.start_session("ssh-01", "192.168.1.100")
        response = honeypot.handle_input(session.session_id, "ls -la")
        response = honeypot.handle_input(session.session_id, "cat /etc/passwd")
        record = honeypot.end_session(session.session_id)
    """

    def __init__(self):
        self._honeypots: dict[str, HoneypotConfig] = {}
        self._sessions: dict[str, HoneypotState] = {}
        self._rl_agent = QLearningAgent()
        self._interaction_history: list[InteractionRecord] = []

        # Fake filesystem for SSH honeypot
        self._fake_filesystem = self._build_fake_filesystem()

        # Fake data for various honeypot types
        self._fake_responses = self._build_fake_responses()

        # Statistics
        self._total_sessions: int = 0
        self._total_dwell_time_s: float = 0.0
        self._total_intelligence_items: int = 0
        self._active_sessions: int = 0

        logger.info("Adaptive honeypot engine initialised")

    def add_honeypot(self, config: HoneypotConfig) -> None:
        """Add a honeypot configuration."""
        self._honeypots[config.honeypot_id] = config
        logger.info(
            f"Honeypot added: {config.honeypot_id} "
            f"({config.honeypot_type.value} on port {config.port})"
        )

    def start_session(
        self,
        honeypot_id: str,
        attacker_ip: str,
        metadata: Optional[dict] = None,
    ) -> Optional[HoneypotState]:
        """
        Start a new honeypot interaction session.

        Args:
            honeypot_id: Which honeypot was accessed.
            attacker_ip: Attacker's IP address.
            metadata: Additional connection metadata.

        Returns:
            HoneypotState for the new session.
        """
        config = self._honeypots.get(honeypot_id)
        if config is None or not config.enabled:
            return None

        session_id = hashlib.sha256(
            f"{honeypot_id}:{attacker_ip}:{time.time()}".encode()
        ).hexdigest()[:16]

        state = HoneypotState(
            session_id=session_id,
            honeypot_type=config.honeypot_type,
            attacker_ip=attacker_ip,
        )

        self._sessions[session_id] = state
        self._total_sessions += 1
        self._active_sessions += 1

        logger.info(
            f"Honeypot session started: {session_id} "
            f"({config.honeypot_type.value}) from {attacker_ip}"
        )

        return state

    def handle_input(
        self,
        session_id: str,
        attacker_input: str,
    ) -> Optional[dict]:
        """
        Handle attacker input and generate adaptive response.

        The RL agent selects the response strategy, the honeypot
        generates the actual response content, and the interaction
        is recorded for intelligence gathering.

        Args:
            session_id: Active session ID.
            attacker_input: What the attacker typed/sent.

        Returns:
            Dict with response content and metadata.
        """
        state = self._sessions.get(session_id)
        if state is None or not state.is_active:
            return None

        config = self._honeypots.get(
            next(
                (hid for hid, cfg in self._honeypots.items()
                 if cfg.honeypot_type == state.honeypot_type),
                None,
            )
        )

        # Update state
        now = time.time()
        state.dwell_time_s = now - state.started_at
        state.last_activity = now
        state.actions_taken += 1
        state.commands_received.append(attacker_input)

        # Check max dwell time
        max_dwell = config.max_dwell_time_s if config else 3600
        if state.dwell_time_s > max_dwell:
            return self._terminate_session(session_id, "max_dwell_time")

        # Gather intelligence from input
        intelligence = self._extract_intelligence(attacker_input, state)
        if intelligence:
            state.intelligence_gathered.append(intelligence)
            self._total_intelligence_items += 1

        # RL agent selects action
        action = self._rl_agent.select_action(state)

        # Update suspicion based on attacker behaviour
        state.suspicion_level = self._estimate_suspicion(state, attacker_input)

        # If suspicion is very high, consider disconnecting
        if state.suspicion_level > 0.9 and action != ResponseAction.DISCONNECT:
            action = ResponseAction.DISCONNECT

        # Generate response based on action
        response = self._generate_response(
            state, config, action, attacker_input
        )

        # Record response
        state.responses_sent.append(response.get("content", "")[:200])

        # Compute reward and update RL agent
        prev_dwell = state.dwell_time_s
        new_dwell = time.time() - state.started_at
        dwell_delta = new_dwell - prev_dwell

        reward = self._rl_agent.compute_reward(
            state, action, dwell_delta, bool(intelligence)
        )

        # Create next state for Q-learning update
        next_state = HoneypotState(
            session_id=state.session_id,
            honeypot_type=state.honeypot_type,
            attacker_ip=state.attacker_ip,
            started_at=state.started_at,
            last_activity=time.time(),
            dwell_time_s=new_dwell,
            actions_taken=state.actions_taken,
            suspicion_level=state.suspicion_level,
            current_depth=state.current_depth,
            is_active=state.is_active,
        )

        self._rl_agent.update(state, action, reward, next_state)

        # Update depth
        if action == ResponseAction.ESCALATE:
            state.current_depth = min(
                state.current_depth + 1,
                config.max_depth if config else 5,
            )

        # Handle disconnect
        if action == ResponseAction.DISCONNECT:
            response["session_ended"] = True
            self.end_session(session_id)

        response["action"] = action.value
        response["reward"] = round(reward, 3)
        response["dwell_time_s"] = round(new_dwell, 1)
        response["suspicion"] = round(state.suspicion_level, 3)
        response["depth"] = state.current_depth

        return response

    def _generate_response(
        self,
        state: HoneypotState,
        config: Optional[HoneypotConfig],
        action: ResponseAction,
        attacker_input: str,
    ) -> dict:
        """Generate honeypot response based on RL action."""
        delay_ms = 0
        content = ""

        if config:
            min_delay, max_delay = config.response_delay_ms
        else:
            min_delay, max_delay = 50, 200

        if action == ResponseAction.ACCEPT:
            content = self._get_fake_response(state.honeypot_type, attacker_input)
            delay_ms = random.randint(min_delay, max_delay)

        elif action == ResponseAction.DELAY:
            content = self._get_fake_response(state.honeypot_type, attacker_input)
            delay_ms = random.randint(max_delay, max_delay * 3)

        elif action == ResponseAction.PARTIAL:
            full_response = self._get_fake_response(state.honeypot_type, attacker_input)
            # Return only partial content
            cutoff = max(10, len(full_response) // 3)
            content = full_response[:cutoff] + "\n... (connection interrupted)"
            delay_ms = random.randint(min_delay, max_delay)

        elif action == ResponseAction.ERROR:
            content = self._get_realistic_error(state.honeypot_type, attacker_input)
            delay_ms = random.randint(min_delay, max_delay)

        elif action == ResponseAction.REDIRECT:
            content = self._get_redirect_response(state.honeypot_type)
            delay_ms = random.randint(min_delay, max_delay)

        elif action == ResponseAction.ESCALATE:
            content = self._get_escalation_response(state.honeypot_type, state.current_depth)
            delay_ms = random.randint(min_delay, max_delay)

        elif action == ResponseAction.DISCONNECT:
            content = "Connection closed by remote host."
            delay_ms = 0

        return {
            "content": content,
            "delay_ms": delay_ms,
            "honeypot_type": state.honeypot_type.value,
        }

    def _get_fake_response(self, hp_type: HoneypotType, command: str) -> str:
        """Generate a fake response for the given command."""
        command_lower = command.lower().strip()

        if hp_type == HoneypotType.SSH:
            return self._ssh_response(command_lower)
        elif hp_type == HoneypotType.HTTP:
            return self._http_response(command_lower)
        elif hp_type == HoneypotType.DATABASE:
            return self._database_response(command_lower)
        elif hp_type == HoneypotType.API:
            return self._api_response(command_lower)
        else:
            return f"OK\n"

    def _ssh_response(self, command: str) -> str:
        """Generate fake SSH shell responses."""
        responses = {
            "ls": "Desktop  Documents  Downloads  .bash_history  .ssh  .env",
            "ls -la": (
                "total 48\n"
                "drwxr-xr-x  8 admin admin 4096 May  4 10:23 .\n"
                "drwxr-xr-x  3 root  root  4096 Apr 15 08:00 ..\n"
                "-rw-------  1 admin admin  892 May  4 10:23 .bash_history\n"
                "-rw-r--r--  1 admin admin  220 Apr 15 08:00 .bash_logout\n"
                "-rw-r--r--  1 admin admin 3771 Apr 15 08:00 .bashrc\n"
                "drwx------  2 admin admin 4096 Apr 20 14:30 .ssh\n"
                "-rw-------  1 admin admin  256 May  1 09:15 .env\n"
                "drwxr-xr-x  2 admin admin 4096 Apr 25 11:00 Documents\n"
                "drwxr-xr-x  2 admin admin 4096 May  3 16:45 Downloads\n"
            ),
            "whoami": "admin",
            "id": "uid=1000(admin) gid=1000(admin) groups=1000(admin),27(sudo),999(docker)",
            "uname -a": "Linux prod-server-03 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux",
            "cat /etc/passwd": (
                "root:x:0:0:root:/root:/bin/bash\n"
                "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                "admin:x:1000:1000:Admin User:/home/admin:/bin/bash\n"
                "postgres:x:112:120:PostgreSQL administrator:/var/lib/postgresql:/bin/bash\n"
                "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
            ),
            "cat .env": (
                "DATABASE_URL=postgresql://app_user:Pr0d_P@ss2024!@db.internal:5432/production\n"
                "API_KEY=sk-canary-fake-key-do-not-use-1234567890\n"
                "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
                "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
                "REDIS_URL=redis://cache.internal:6379/0\n"
            ),
            "pwd": "/home/admin",
            "hostname": "prod-server-03",
            "ifconfig": (
                "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
                "        inet 10.0.1.23  netmask 255.255.255.0  broadcast 10.0.1.255\n"
                "        ether 02:42:0a:00:01:17  txqueuelen 0  (Ethernet)\n"
            ),
            "ps aux": (
                "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
                "root         1  0.0  0.1 169316 11200 ?        Ss   May04   0:03 /sbin/init\n"
                "postgres   412  0.1  2.3 215432 47200 ?        Ss   May04   1:23 /usr/lib/postgresql/14/bin/postgres\n"
                "www-data   523  0.0  1.1 142568 22400 ?        S    May04   0:45 nginx: worker process\n"
                "admin     1024  0.0  0.3  21464  5600 pts/0    Ss   10:23   0:00 -bash\n"
            ),
            "netstat -tlnp": (
                "Active Internet connections (only servers)\n"
                "Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name\n"
                "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      234/sshd\n"
                "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      523/nginx\n"
                "tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN      523/nginx\n"
                "tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN      412/postgres\n"
                "tcp        0      0 127.0.0.1:6379          0.0.0.0:*               LISTEN      389/redis-server\n"
            ),
        }

        # Check for exact match
        for key, response in responses.items():
            if command == key or command.startswith(key.split()[0]):
                return response

        # Default: command not found
        cmd_name = command.split()[0] if command else "unknown"
        return f"-bash: {cmd_name}: command not found"

    def _http_response(self, request: str) -> str:
        """Generate fake HTTP responses."""
        return (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html\r\n"
            "Server: nginx/1.24.0\r\n\r\n"
            "<html><head><title>Login</title></head>"
            "<body><form method='POST' action='/auth'>"
            "<input name='username' placeholder='Username'>"
            "<input name='password' type='password' placeholder='Password'>"
            "<button type='submit'>Sign In</button>"
            "</form></body></html>"
        )

    def _database_response(self, query: str) -> str:
        """Generate fake database responses."""
        if "select" in query:
            return (
                " id | username | email | role\n"
                "----+----------+-------------------+-------\n"
                "  1 | admin    | admin@company.com | admin\n"
                "  2 | jsmith   | j.smith@company.com | user\n"
                "  3 | mwilson  | m.wilson@company.com | user\n"
                "(3 rows)\n"
            )
        elif "show" in query:
            return (
                "  Schema  |        Name        | Type  | Owner\n"
                "---------+--------------------+-------+-------\n"
                " public  | users              | table | admin\n"
                " public  | transactions       | table | admin\n"
                " public  | audit_log          | table | admin\n"
                " public  | api_keys           | table | admin\n"
            )
        return "ERROR:  syntax error at or near \"" + query[:20] + "\""

    def _api_response(self, request: str) -> str:
        """Generate fake API responses."""
        return (
            '{"status": "success", "data": {'
            '"users_count": 1247, '
            '"active_sessions": 89, '
            '"api_version": "2.1.0", '
            '"server": "prod-api-03"'
            '}}'
        )

    def _get_realistic_error(self, hp_type: HoneypotType, command: str) -> str:
        """Generate realistic error messages."""
        errors = {
            HoneypotType.SSH: [
                "Permission denied",
                "No such file or directory",
                "Connection timed out",
                "Segmentation fault (core dumped)",
                "Too many open files",
            ],
            HoneypotType.HTTP: [
                "HTTP/1.1 403 Forbidden\r\n\r\nAccess Denied",
                "HTTP/1.1 500 Internal Server Error\r\n\r\nServer Error",
                "HTTP/1.1 429 Too Many Requests\r\n\r\nRate Limited",
            ],
            HoneypotType.DATABASE: [
                "ERROR: permission denied for table users",
                "ERROR: connection limit exceeded for non-superusers",
                "FATAL: too many connections for role \"app_user\"",
            ],
            HoneypotType.API: [
                '{"error": "rate_limit_exceeded", "retry_after": 60}',
                '{"error": "insufficient_permissions", "required": "admin"}',
                '{"error": "internal_server_error", "request_id": "req_abc123"}',
            ],
        }

        type_errors = errors.get(hp_type, ["Error"])
        return random.choice(type_errors)

    def _get_redirect_response(self, hp_type: HoneypotType) -> str:
        """Generate redirect response to deeper honeypot."""
        return (
            "Connecting to internal service...\n"
            "Authenticated. Redirecting to management console.\n"
            "Type 'help' for available commands.\n"
        )

    def _get_escalation_response(self, hp_type: HoneypotType, depth: int) -> str:
        """Generate escalation response with richer content."""
        if depth == 1:
            return "Access granted. Welcome to the management interface.\n"
        elif depth == 2:
            return "Elevated privileges granted. Database access enabled.\n"
        elif depth == 3:
            return "Root access obtained. Full system control available.\n"
        else:
            return "Maximum access level reached.\n"

    # ------------------------------------------------------------------
    # INTELLIGENCE EXTRACTION
    # ------------------------------------------------------------------

    def _extract_intelligence(
        self,
        attacker_input: str,
        state: HoneypotState,
    ) -> Optional[dict]:
        """
        Extract intelligence from attacker input.

        Captures:
        - Tools used (nmap, metasploit, sqlmap, etc.)
        - Techniques (enumeration, privilege escalation, etc.)
        - Objectives (data exfiltration, lateral movement, etc.)
        - Credentials attempted
        - Payloads deployed
        """
        intel = {}
        input_lower = attacker_input.lower()

        # Tool detection
        tools = {
            "nmap": "nmap",
            "metasploit": "metasploit",
            "sqlmap": "sqlmap",
            "hydra": "hydra",
            "john": "john_the_ripper",
            "hashcat": "hashcat",
            "burp": "burp_suite",
            "nikto": "nikto",
            "dirb": "dirb",
            "gobuster": "gobuster",
            "wget": "wget",
            "curl": "curl",
            "nc ": "netcat",
            "netcat": "netcat",
            "python": "python_script",
            "perl": "perl_script",
            "powershell": "powershell",
        }

        for keyword, tool_name in tools.items():
            if keyword in input_lower:
                intel["tool_detected"] = tool_name

        # Technique detection
        if any(kw in input_lower for kw in ["cat /etc/passwd", "cat /etc/shadow", "/etc/group"]):
            intel["technique"] = "credential_harvesting"
        elif any(kw in input_lower for kw in ["sudo", "su -", "chmod +s", "setuid"]):
            intel["technique"] = "privilege_escalation"
        elif any(kw in input_lower for kw in ["scp", "wget", "curl -o", "nc -l"]):
            intel["technique"] = "data_exfiltration"
        elif any(kw in input_lower for kw in ["ssh ", "rdp", "psexec", "wmi"]):
            intel["technique"] = "lateral_movement"
        elif any(kw in input_lower for kw in ["crontab", "systemctl", "rc.local", ".bashrc"]):
            intel["technique"] = "persistence"
        elif any(kw in input_lower for kw in ["rm -rf", "shred", "wipe", "dd if=/dev/zero"]):
            intel["technique"] = "anti_forensics"
        elif any(kw in input_lower for kw in ["ifconfig", "ip addr", "arp", "route"]):
            intel["technique"] = "network_reconnaissance"
        elif any(kw in input_lower for kw in ["select", "insert", "update", "drop", "union"]):
            intel["technique"] = "sql_injection"

        # Objective detection
        if any(kw in input_lower for kw in [".env", "config", "credentials", "password", "secret"]):
            intel["objective"] = "credential_theft"
        elif any(kw in input_lower for kw in ["database", "dump", "backup", "export"]):
            intel["objective"] = "data_theft"
        elif any(kw in input_lower for kw in ["encrypt", "ransom", "bitcoin", "wallet"]):
            intel["objective"] = "ransomware"
        elif any(kw in input_lower for kw in ["botnet", "c2", "beacon", "callback"]):
            intel["objective"] = "command_and_control"

        if intel:
            intel["timestamp"] = datetime.now(timezone.utc).isoformat()
            intel["raw_input"] = attacker_input[:200]
            intel["session_id"] = state.session_id
            return intel

        return None

    def _estimate_suspicion(
        self,
        state: HoneypotState,
        attacker_input: str,
    ) -> float:
        """
        Estimate attacker's suspicion level.

        Increases when:
        - Responses are too slow or too fast
        - Content seems too easy to access
        - Attacker probes for honeypot indicators
        - Interaction pattern is unusual

        Decreases when:
        - Responses are realistic
        - Errors occur naturally
        - System behaves like a real server
        """
        suspicion = state.suspicion_level
        input_lower = attacker_input.lower()

        # Honeypot detection attempts increase suspicion
        honeypot_probes = [
            "honeypot", "canary", "cowrie", "kippo", "dionaea",
            "honeyd", "glastopf", "conpot", "fake", "trap",
            "sandbox", "decoy",
        ]

        for probe in honeypot_probes:
            if probe in input_lower:
                suspicion += 0.3
                logger.warning(
                    f"Honeypot probe detected in session {state.session_id}: "
                    f"'{probe}'"
                )

        # Too many commands too fast = automated tool (less suspicious of honeypot)
        if state.actions_taken > 0:
            actions_per_second = state.actions_taken / max(1, state.dwell_time_s)
            if actions_per_second > 2.0:
                suspicion -= 0.05  # Automated tools don't check for honeypots

        # Very specific probing increases suspicion
        if any(kw in input_lower for kw in [
            "uptime", "/proc/cpuinfo", "dmidecode", "lshw",
        ]):
            suspicion += 0.05  # Checking hardware = might be checking for VM/honeypot

        # Natural decay over time (attacker gets comfortable)
        if state.dwell_time_s > 60:
            suspicion *= 0.99

        return max(0.0, min(1.0, suspicion))

    def end_session(self, session_id: str) -> Optional[InteractionRecord]:
        """End a honeypot session and record the interaction."""
        state = self._sessions.pop(session_id, None)
        if state is None:
            return None

        state.is_active = False
        now = datetime.now(timezone.utc)
        dwell_time = time.time() - state.started_at

        record = InteractionRecord(
            session_id=session_id,
            honeypot_type=state.honeypot_type,
            attacker_ip=state.attacker_ip,
            started_at=datetime.fromtimestamp(
                state.started_at, tz=timezone.utc
            ).isoformat(),
            ended_at=now.isoformat(),
            dwell_time_s=round(dwell_time, 2),
            actions_taken=state.actions_taken,
            commands=state.commands_received,
            intelligence=state.intelligence_gathered,
            max_depth_reached=state.current_depth,
            suspicion_at_end=state.suspicion_level,
            total_reward=0.0,
        )

        self._interaction_history.append(record)
        self._total_dwell_time_s += dwell_time
        self._active_sessions -= 1

        logger.info(
            f"Honeypot session ended: {session_id}, "
            f"dwell={dwell_time:.1f}s, actions={state.actions_taken}, "
            f"intelligence={len(state.intelligence_gathered)}, "
            f"depth={state.current_depth}, "
            f"suspicion={state.suspicion_level:.2f}"
        )

        return record

    def _terminate_session(self, session_id: str, reason: str) -> dict:
        """Terminate a session due to limits."""
        self.end_session(session_id)
        return {
            "content": "Connection closed.",
            "session_ended": True,
            "reason": reason,
        }

    def _build_fake_filesystem(self) -> dict:
        """Build a realistic-looking fake filesystem."""
        return {
            "/": ["bin", "etc", "home", "var", "tmp", "opt", "usr"],
            "/home": ["admin", "deploy"],
            "/home/admin": [
                ".bash_history", ".ssh", ".env", "Documents",
                "Downloads", "scripts", "backups",
            ],
            "/home/admin/.ssh": ["authorized_keys", "id_rsa", "id_rsa.pub", "known_hosts"],
            "/home/admin/Documents": [
                "budget_2024.xlsx", "passwords.txt",
                "network_diagram.pdf", "api_keys.json",
            ],
            "/etc": [
                "passwd", "shadow", "hosts", "nginx",
                "postgresql", "ssh", "crontab",
            ],
            "/var": ["log", "www", "lib", "backups"],
            "/var/log": ["auth.log", "syslog", "nginx", "postgresql"],
            "/var/www": ["html", "api", "admin"],
        }

    def _build_fake_responses(self) -> dict:
        """Build fake response templates."""
        return {}  # Responses are generated dynamically

    # ------------------------------------------------------------------
    # QUERY METHODS
    # ------------------------------------------------------------------

    def get_active_sessions(self) -> list[dict]:
        """Get all active honeypot sessions."""
        now = time.time()
        return [
            {
                "session_id": state.session_id,
                "honeypot_type": state.honeypot_type.value,
                "attacker_ip": state.attacker_ip,
                "dwell_time_s": round(now - state.started_at, 1),
                "actions_taken": state.actions_taken,
                "suspicion_level": round(state.suspicion_level, 3),
                "depth": state.current_depth,
                "intelligence_items": len(state.intelligence_gathered),
            }
            for state in self._sessions.values()
            if state.is_active
        ]

    def get_interaction_history(self, limit: int = 50) -> list[dict]:
        """Get recent interaction records."""
        return [
            {
                "session_id": r.session_id,
                "honeypot_type": r.honeypot_type.value,
                "attacker_ip": r.attacker_ip,
                "started_at": r.started_at,
                "ended_at": r.ended_at,
                "dwell_time_s": r.dwell_time_s,
                "actions_taken": r.actions_taken,
                "intelligence_count": len(r.intelligence),
                "max_depth": r.max_depth_reached,
                "suspicion": round(r.suspicion_at_end, 3),
            }
            for r in self._interaction_history[-limit:]
        ]

    def get_stats(self) -> dict:
        """Return honeypot engine statistics."""
        avg_dwell = (
            self._total_dwell_time_s / self._total_sessions
            if self._total_sessions > 0
            else 0.0
        )

        return {
            "total_sessions": self._total_sessions,
            "active_sessions": self._active_sessions,
            "total_dwell_time_s": round(self._total_dwell_time_s, 1),
            "avg_dwell_time_s": round(avg_dwell, 1),
            "total_intelligence_items": self._total_intelligence_items,
            "honeypots_configured": len(self._honeypots),
            "honeypot_types": [
                {
                    "id": hid,
                    "type": cfg.honeypot_type.value,
                    "port": cfg.port,
                    "enabled": cfg.enabled,
                }
                for hid, cfg in self._honeypots.items()
            ],
            "rl_agent": self._rl_agent.get_stats(),
            "interaction_history_size": len(self._interaction_history),
        }


# Module-level singleton
_honeypot: Optional[AdaptiveHoneypot] = None


def get_adaptive_honeypot() -> AdaptiveHoneypot:
    """Get or create the singleton AdaptiveHoneypot instance."""
    global _honeypot
    if _honeypot is None:
        _honeypot = AdaptiveHoneypot()

        # Deploy default honeypots
        _honeypot.add_honeypot(HoneypotConfig(
            honeypot_id="ssh-01",
            honeypot_type=HoneypotType.SSH,
            port=2222,
            hostname="prod-server-03",
            service_banner="SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
        ))
        _honeypot.add_honeypot(HoneypotConfig(
            honeypot_id="http-01",
            honeypot_type=HoneypotType.HTTP,
            port=8080,
            hostname="web-admin-01",
            service_banner="nginx/1.24.0",
        ))
        _honeypot.add_honeypot(HoneypotConfig(
            honeypot_id="db-01",
            honeypot_type=HoneypotType.DATABASE,
            port=5433,
            hostname="db-replica-02",
            service_banner="PostgreSQL 14.10",
        ))
        _honeypot.add_honeypot(HoneypotConfig(
            honeypot_id="api-01",
            honeypot_type=HoneypotType.API,
            port=9090,
            hostname="api-internal-01",
            service_banner="",
        ))

    return _honeypot
