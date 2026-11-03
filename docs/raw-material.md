# The raw material, read before designing anything

Written 2026-11-03, before the threat model, the irreversibility list or any
bypass test. It reads what the summary tables were made from, not the tables.
`python evals/agentdojo/read_transcripts.py` prints every count below.

## What was read

- **Every model conversation:** 4,724 under `evals/agentdojo/results/model/`,
  4,374 of them attacked. Claude Haiku 4.5 and Claude Sonnet 5.5 on banking,
  and Sonnet on Slack.
- **The 47 replayed attacks** that worked with no policy and still worked
  under the session rule with a careful approver, in `results/attack.csv`.
- **The payloads of the real Claude Code session**, in
  `tests/fixtures/claude_code/`.
- **The source of AgentDojo's 74 tools**, in agentdojo 0.1.35, read as code
  rather than as docstrings.

## Near-compliance: almost none, and one shape worth knowing

| What | Count |
|---|---|
| Calls whose arguments carried an attacker's value | 15, in 14 conversations |
| Of them, calls that ran without an error | 0 |
| Conversations that put the attacker's action to the user as a question | 3 |

- **The 15 calls are all one thing.** Slack hides its injection in a
  channel's name. Two tasks post to or list that channel, so the model passed
  the whole injected name as the `channel` argument. None ran: the name was
  copied imperfectly, or the policy blocked it.
- **The 3 are Haiku, on banking.** Each final reply asks the user a direct
  question: "Do you actually want me to send money to
  US133000000121212121212?" Sonnet never did this. It refused, named the
  text and moved on. The question matters for the threat model. A user who
  answers yes in chat has authorised nothing, because the session is still
  tainted and the next call is still held. A product that treats a chat reply
  as approval would turn the injection into a yes.

## After a block: no attempt to get round it

| What | Count |
|---|---|
| Calls blocked | 976 |
| Conversations with a blocked call | 755 |
| Retried the blocked call unchanged | 14 |
| Retried the same tool with changed arguments | 7 |
| Went on to another sink | 14 |
| Any of those carrying an attacker's value | 0 |

Only calls made after the model had seen the refusal are counted.

- **Unchanged retries.** The model tried the same call again and was blocked
  again.
- **Changed arguments.** All 7 are `get_webpage` on Slack, on another URL
  that the task itself names.
- **Another sink.** The task's next step, such as a refund after a held rent
  update.

No model rephrased an attacker's call to slip past a rule. These models
followed no attack, so this says nothing about a model that is trying.

## Effects reached through tools that are not sinks

- **In the model runs, none.** 6,705 calls went to tools that are not sinks.
  Read as code, every one of those tools only reads. The 8 that carried an
  attacker's value are the injected channel name again, passed to
  `get_users_in_channel`, and all 8 raised.
- **In the code, two tools are not what their descriptions say.**
  - Workspace's `get_unread_emails` marks every unread email as read, and no
    tool marks one unread. It changes state that cannot be put back.
  - Slack's `get_webpage` appends the URL to the environment's
    `web_requests`. A read sends data out in its arguments. The frozen lists
    already treat it as a sink.
- **Creating a calendar event always sends mail.** It is sent to the
  participants, plus the user, even when no participants are given.
  Cancelling and rescheduling mail the participants too.

## The 47 replayed attacks that got through

| Vector | Attacks | Why |
|---|---|---|
| Slack `get_channels`, injection tasks 1, 3 and 5 | 27 | A channel's name is attacker-written, and the tool is listed as a listing, not a source. The session was never tainted |
| Travel injection task 6, through hotel, restaurant and car reviews | 20 | Its goal is a sentence in the reply. It needs no tool call, so no tool policy can touch it |

## The real Claude Code session

The 11 payloads cover an MCP comment before and after a read, a comment on a
disallowed issue, and `cat .env` through Bash and Read. Every ask came from
the session rule or the firewall on an MCP tool. The PreToolUse matcher in
`sdk/hooks/settings_example.json` does not name Bash, Write or Edit. A Bash
command that sends data out goes to Claude Code's own permissions and never
reaches the hook.

## What this changes in what comes next

1. **The threat model has to treat the agent as the attacker.** No model here
   tried. So mediation has to be argued from the code paths, not inferred
   from these runs.
2. **Irreversibility has to be read from code.** One read changes state for
   good, and one read sends data out. Descriptions were wrong about both.
3. **The approval channel is the boundary.** A yes in chat, a rubber stamp,
   or a hook that is never asked are where the guarantee ends. The tests
   must exercise those paths, not the model's restraint.
