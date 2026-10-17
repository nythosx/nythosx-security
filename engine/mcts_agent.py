import random
import math
import json
from .state_machine import AppState
from .invariants import InvariantOracle

class MCTSNode:
    def __init__(self, state, parent=None, action=None):
        self.state = state
        self.parent = parent
        self.action = action
        self.children = []
        self.visits = 0
        self.value = 0.0

    def ucb1(self, c=1.414):
        if self.visits == 0:
            return float('inf')
        return (self.value / self.visits) + c * math.sqrt(math.log(self.parent.visits) / self.visits)

class MCTSAgent:
    def __init__(self, llm_client=None, oracle=None, max_rollouts=50):
        self.llm_client = llm_client
        self.oracle = oracle or InvariantOracle()
        self.max_rollouts = max_rollouts
        self.root = None

    def search(self, initial_state, http_client):
        self.root = MCTSNode(initial_state)
        for _ in range(self.max_rollouts):
            node = self._select(self.root)
            if not node.children and node.visits > 0:
                self._expand(node, http_client)
            if node.children:
                child = random.choice(node.children)
                reward = self._simulate(child, http_client)
                self._backpropagate(child, reward)
        return self._best_path(self.root)

    def _select(self, node):
        while node.children:
            node = max(node.children, key=lambda c: c.ucb1())
        return node

    def _expand(self, node, http_client):
        actions = self._propose_actions(node.state)
        for action in actions:
            new_state = self._apply_action(node.state, action, http_client)
            child = MCTSNode(new_state, parent=node, action=action)
            node.children.append(child)

    def _propose_actions(self, state):
        if not self.llm_client:
            return []
        try:
            prompt = (
                "Given application state, propose 3 to 5 HTTP actions to test "
                "business invariants. Return JSON only: "
                '{"actions": [{"method": str, "url": str, "payload": {}}]}\n'
                + json.dumps({
                    "state_name": state.name,
                    "variables": state.variables,
                    "history_tail": state.history[-5:],
                }, default=str)[:4000]
            )
            raw = self.llm_client(prompt)
            data = json.loads(raw)
            actions = data.get("actions") or []
            return [a for a in actions
                    if isinstance(a, dict) and a.get("method") and a.get("url")][:5]
        except Exception:
            return []

    def _apply_action(self, state, action, http_client):
        new_state = AppState(name=f"{state.name}_{action.get('method')}")
        new_state.context_wallet = state.context_wallet
        new_state.variables = dict(state.variables)
        new_state.history = list(state.history)
        
        res = http_client.request(action.get("method", "GET"), action.get("url", "/"), 
                                  json=action.get("payload"))
        status = res.status_code if hasattr(res, "status_code") else res.get("status", 0)
        body = res.text if hasattr(res, "text") else res.get("body", "")
        new_state.record_action(action.get("method"), action.get("url"), status, body)
        return new_state

    def _simulate(self, node, http_client):
        violations = self.oracle.evaluate_all(node.state.variables)
        if violations:
            return 1.0
        return 0.0

    def _backpropagate(self, node, reward):
        while node:
            node.visits += 1
            node.value += reward
            node = node.parent

    def _best_path(self, node):
        path = []
        while node.children:
            node = max(node.children, key=lambda c: c.visits)
            path.append({"action": node.action, "state": node.state.name, "visits": node.visits})
        return path
