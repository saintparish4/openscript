# Exploratory: ask only about new destinations

**Not a protocol result.** This was tried on 2026-10-14, after the model runs
had been seen, to decide whether one idea is worth building and measuring
properly. Nothing here was frozen beforehand, the rule was written knowing the
results it would be scored on, and it covers one suite. Quote it as an early
experiment or not at all.

## The question

The session rule (`SessionTaintPolicy`) holds every state-changing call once a
session has read untrusted content. With Claude Sonnet 5.5 doing AgentDojo's
banking tasks it asked a person on 11 of 16 ordinary tasks, as often as asking
on every state-changing call ([`docs/metrics.md`](../../../docs/metrics.md#tool-policies-on-agentdojo-with-a-model-in-the-loop)).
Would it ask rarely if it held only calls that send money somewhere the account
has not paid before?

## The rule tried

After an untrusted read, a state-changing call needs a person unless:

- it pays (`send_money`, `schedule_transaction`) an account the user has
  already paid, in the history or a scheduled payment, as it stood before any
  task ran; or
- it changes a scheduled payment without changing who it goes to, or moves it
  to such an account.

A password or an address change always needs a person: there is no destination
to know. Accounts that have only *paid the user* do not count as known,
because anyone can send a cent to become one.

The firewall cannot express this today. It can refuse any destination that is
not listed, or ask on every call to a tool, but not ask only when the
destination is new. So this counts what such a rule would have asked; it does
not run one.

## What it found

`known_payees.py`, from `evals/agentdojo` (`.venv/bin/python exploratory/known_payees.py`):

| Ordinary banking tasks needing a person | Session rule | Ask only about new destinations |
|---|---|---|
| AgentDojo's own solutions (the replay) | 12/16 | 5/16 |
| Claude Sonnet 5.5's recorded calls | 11/16 | **4/16** |
| Claude Haiku 4.5's recorded calls | 4/16 | 2/16 |

- **Every attack is still held.** All eleven of the attackers' state-changing
  calls in banking go to the attacker's account or change the password, and
  the rule holds every one.
- **The model rows are exact.** Those runs had a careful approver who approved
  every ordinary call, so whether a call was held did not change what the model
  did next. The calls are counted again under the new rule, and the old rule's
  count is checked against the recorded approvals first: it matches on every
  task.
- **What still asks is what should.** Paying a new payee taken from a bill
  (`user_task_0`), and changing an address or a password (`user_task_13`,
  `user_task_14`). In the replay, `user_task_5` and `user_task_11` also ask
  because AgentDojo's solutions pay "Spotify" and "Apple" by name, not by
  account; the models used the account numbers.

## What it cannot say

- **One suite, and the friendliest.** Banking has four known payees and
  destinations that are account numbers. The replay's approvals were mostly in
  the email and Slack suites, where a known destination still has to be
  defined: contacts, members, channels, URLs.
- **An attack that uses a known payee is not held.** Paying a known account too
  much is what the firewall's numeric bounds are for, and they are not part of
  this count.
- **It was designed after the results.** Before any number from it is
  published as a result it needs a protocol frozen first, the rule built as a
  real option, and every suite.
